#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <ucontext.h>
#include <dirent.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <sys/ucontext.h>
#include <sys/resource.h>
#include <linux/futex.h>

#include "syscall_wrapper.h"
#include "color_allocator.h"

#define FN_NON_MATCHING "/dev/color_non_matching"
// Force the stack size to 1 MB
#define STACK_SIZE (1 << 20)

enum memory_region_type {
    mem_type_none = 0,
    mem_type_regular,
    mem_type_stack,
    mem_type_vdso,
};

// Describes a mapped memory region
struct {
    unsigned char *base; // Start of memory region, must be page-aligned
    unsigned char *end; // End of memory region, must be page-aligned
    enum memory_region_type type; // Type of memory region (regular or vdso)
    unsigned char permissions; // mmap prot attributes (PROT_READ | PROT_WRITE | PROT_EXEC)
    unsigned char jump_into_backup; // Do we have to jump into backup code when unmapping this region?
} typedef mem_region;

static unsigned char migration_done = 0;

static unsigned int discrete_log2(unsigned long n) {
    unsigned int r = 0;
    if (!n)
        return 0;
    while (n >> ++r);
    return r - 1;
}

static void free_text_regions(mem_region *regions) {
    free(regions);
}

static unsigned int parse_memory_regions(FILE *maps, mem_region **regions, unsigned long vdso_base) {
    char *line = NULL;
    unsigned long count = 0, start, end;
    size_t len = 0;
    char perms[3] = {0,};
    unsigned char vdso;
    int status;
    struct robust_list* futex_head = NULL;
    size_t futex_len;

    // Get address of futex list, since unmapping this leads to immeadiate SIGSEGV
    syscall(SYS_get_robust_list, getpid(), &futex_head, &futex_len);

    *regions = malloc(0);

    while (getline(&line, &len, maps) > 0) {
        status = sscanf(line, "%lx-%lx %c%c%c", &start, &end, &perms[0], &perms[1], &perms[2]);
        vdso = (strstr(line, "[vvar]") != NULL || strstr(line, "[vdso]") != NULL || strstr(line, "[vsyscall]") != NULL || start == vdso_base) ? 1 : 0;
        free(line);
        line = NULL;
        if (status != 5)
            continue;

        *regions = realloc(*regions, sizeof(**regions) * (count + 2));
        if (!*regions)
            exit(EXIT_FAILURE);

        (*regions)[count].base = (void *) start;
        (*regions)[count].end = (void *) end;
        (*regions)[count].type = mem_type_regular;
        (*regions)[count].permissions = (perms[0] == 'r' ? PROT_READ : 0) | (perms[1] == 'w' ? PROT_WRITE : 0) | (
                                            perms[2] == 'x' ? PROT_EXEC : 0);
        (*regions)[count].jump_into_backup =
                (start <= (size_t) parse_memory_regions && end > (size_t) parse_memory_regions) ? 1 : 0;
        if (vdso) {
            (*regions)[count].type = mem_type_vdso;
            if (count && (*regions)[count - 1].type != mem_type_stack)
                (*regions)[count - 1].type = mem_type_vdso;
        }
        if ((*regions)[count].base <= (unsigned char*) futex_head && (*regions)[count].end > (unsigned char*) futex_head)
            (*regions)[count].type = mem_type_vdso;
        if ((*regions)[count].base <= (unsigned char*) &futex_head && (*regions)[count].end > (unsigned char*) &futex_head)
            (*regions)[count].type = mem_type_stack;

        count++;
    }

    return count;
}

static int get_memory_regions(mem_region **out) {
    const unsigned long vdso_base = getauxval(AT_SYSINFO_EHDR);
    const static char mpath[] = "/proc/self/maps";
    ssize_t count = 0;
    FILE *maps = NULL;

    maps = fopen(mpath, "r");
    if (!maps)
        return -1;

    *out = NULL;
    count = parse_memory_regions(maps, out, vdso_base);
    (*out)[count].type = 0;

    fclose(maps);
    return 0;
}

/**
 * Unmap the code specified by space, remap it, and fill it with the data in dest
 *
 * @param space A text_region describing the code section that should be remapped
 * @param dest A backup buffer containing the code in space. It must have the same size
 *
 * @returns 0 upon success, a negative value otherwise
*/
static __attribute__((optimize("O0"))) int remap_no_libc(const mem_region *space, const unsigned char *dest, int fd) {
    long status;
    unsigned int i;
    unsigned long rptr;
    ssize_t size = space->end - space->base, size_new = size;

    if (space->type == mem_type_stack)
        size_new = STACK_SIZE;

    /*
    remap_no_libc must work in an environment where the GOT is unavailable,
    which means that we cannot use any shared libraries whatsoever.
    This unfortunately includes libc, so we have to inline absolutely
    everything, including syscalls and memcpy. Also, we cannot use compiler
    optimizations for this code, as the compiler may attempt to insert calls
    to libc for better performance.
    */

    // Munmap old section
    status = (long) syscall_wrapper2(SYS_munmap, (unsigned long) space->base, size);

    // If there is an error, we can do nothing but quit
    if (status != 0)
        syscall_wrapper1(SYS_exit, 99); // exit(1)

    // Remap new section
    rptr = syscall_wrapper6(SYS_mmap, (unsigned long) space->base,
                            size_new, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | (fd == -1 ? MAP_ANONYMOUS : 0), fd,
                            0);
    if ((void *) rptr != space->base)
        syscall_wrapper1(SYS_exit, -rptr); // exit(errno)

    // Copy from backup into new section
    for (i = 0; i < (space->end - space->base) / sizeof(uintptr_t); i++)
        ((uintptr_t *) space->base)[i] = ((size_t *) (dest))[i];

    syscall_wrapper3(SYS_mprotect, (unsigned long) rptr, size, space->permissions);

    return 0;
}

// Migrate a single text section
static int migrate_memory_section(mem_region *space, unsigned long page_shift, int fd) {
    int status;
    unsigned char *dest;
    size_t num_pages = (space->end - space->base) >> page_shift;
    int (*remap_function)(const mem_region *, const unsigned char *, int);

    // Skip guard page if it exists
    if (!(space->permissions & PROT_READ))
        return 0;

    // Mmap backup
    dest = mmap(NULL, num_pages << page_shift, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (dest == MAP_FAILED)
        return -1;

    // Copy code
    memcpy(dest, space->base, num_pages << page_shift);

    remap_function = remap_no_libc;

    // We cannot unmap the code we are currently executing. If this needs to be done, jump
    // into the backup and do it from there
    if (space->jump_into_backup) {
        mprotect(dest, num_pages << page_shift, PROT_READ | PROT_EXEC);
        remap_function = (void *) ((size_t) remap_function + (dest - space->base));
    }

    // Remap code into buffer
    status = remap_function(space, dest, fd);

    // Unmap backup
    munmap(dest, num_pages << page_shift);
    return status;
}

static void migrate_regions(const mem_region *regions, unsigned long page_size, int fd) {
    mem_region region_local;

    while (regions->type != mem_type_none) {
        // Make copy of current segment on stack in case we have to unmap global data
        memcpy(&region_local, regions, sizeof(region_local));
        regions++;

        // VDSO belongs to the kernel, so don't mess with that
        if (region_local.type == mem_type_vdso)
            continue;

        // Migrate segment
        migrate_memory_section(&region_local, discrete_log2(page_size), fd);
    }
}

static int find_file_descriptor(const char *filename) {
    struct dirent *entry;
    char path[PATH_MAX];
    char resolved_path[PATH_MAX];
    int fd = -1;
    size_t len;
    DIR *dir = opendir("/proc/self/fd");
    
    if (!dir) {
        perror("opendir");
        return -1;
    }

    // Iterate over all file descriptors
    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Construct the path to the file descriptor link
        snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);

        // Resolve the symbolic link
        len = readlink(path, resolved_path, sizeof(resolved_path) - 1);
        if (len == -1) {
            perror("readlink");
            continue;
        }
        resolved_path[len] = '\0'; // Null-terminate the string

        // Compare the resolved path with the given filename
        if (strcmp(resolved_path, filename) == 0) {
            fd = atoi(entry->d_name);
            break;
        }
    }

    closedir(dir);
    return fd;
}

int migrate_all(int fd, unsigned long stack_size_limit) {
    const unsigned long page_size = getpagesize();
    int rc;
    struct rlimit rl;
    unsigned char *temporary_stack;
    ucontext_t old_context, new_context;
    mem_region *regions = NULL;

    // Get info about mapped memory
    if (get_memory_regions(&regions) != 0) {
        perror("get_memory_regions");
        return -EFAULT;
    }

    // Allocate temporary stack for use during the migration process
    // If we did not do this, we would eventually unmap our working data and crash
    temporary_stack = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    // Run 'migrate' on temporary stack
    getcontext(&new_context);
    new_context.uc_stack.ss_sp = temporary_stack;
    new_context.uc_stack.ss_size = page_size;
    new_context.uc_link = &old_context;
    makecontext(&new_context, (void *) migrate_regions, 3, regions, page_size, fd);
    swapcontext(&old_context, &new_context); // <- migrate is invoked here

    // Unmap the temporary stack again
    munmap(temporary_stack, page_size);

    free_text_regions(regions);

    // Limit stack size
    rl.rlim_cur = rl.rlim_max = stack_size_limit;
    if (setrlimit(RLIMIT_STACK, &rl) != 0) {
        perror("setrlimit failed");
        return -EINVAL;
    }

    // Instruct the kernel module to redirect all future allocations to fd
    rc = ioctl(fd, IOCTL_LOCK);
    if (rc < 0 && errno != EEXIST) {
        fprintf(stderr, "Ioctl LOCK failed with errno %d\n", errno);
        return rc;
    }

    migration_done = 1;

    return 0;
}

unsigned char has_migrated(void) {
    return migration_done;
}

__attribute__((constructor))
void migrator_main(void) {
    const char* fn;
    int fd;

    // If the user configured a migration file, do the migration now. Otherwise, the program must do this later.
    fn = getenv("ALLOC_FILE");
    if (!fn)
        return;

    fd = open(fn, O_RDWR);
    if (fd < 0) {
        if (errno == EEXIST)
            fd = find_file_descriptor(fn);
        if (fd < 0) {
            fprintf(stderr, "Warning: Could not open '%s'! Make sure that you have loaded the kernel module. Continuing without migration...\n", fn);
            fflush(stderr);
            return;
        }
    }

    migrate_all(fd, 0);
}
