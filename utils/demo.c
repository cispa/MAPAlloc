#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include "color_allocator.h"

#define str(x) #x
#define stringify(x) str(x)

#define expression ((x >> 12) & 31) == 5
#define EXPR stringify(expression)

static unsigned char eval_address(unsigned long x) {
    return expression ? 1 : 0;
}

static size_t get_physical_address(size_t vaddr) {
    int fd = open("/proc/self/pagemap", O_RDONLY);
    uint64_t virtual_addr = (uint64_t)vaddr;
    size_t value = 0;
    off_t offset = (virtual_addr / 4096) * sizeof(value);
    int got = pread(fd, &value, sizeof(value), offset);
    if(got != sizeof(value)) {
        return 0;
    }
    close(fd);
    return (value << 12) | ((size_t)vaddr & 0xFFFULL);
}

int main() {
    const unsigned long page_size = getpagesize();
    unsigned long mem_free_pre, mem_free_post, paddr;
    int root_fd, fd_match, fd_non_match, ioctl_ret;
    unsigned char* match_range, *non_match_range;
    char fname[64];
    mmap_ioctl_arg arg;
    ioctl_new_exrp_arg new_arg;
    ioctl_delete_exrp_arg del_arg;

    memset(&new_arg, 0, sizeof(new_arg));
    memset(&del_arg, 0, sizeof(del_arg));

    // Open root device
    root_fd = open("/dev/" ALLOC_ROOT_FILE_NAME, O_RDWR);
    if (root_fd < 0) {
        fprintf(stderr, "Could not open root - errno %d\n", errno);
        return 1;
    }

    printf ("Creating a new allocator instance with expression '" EXPR "' ... ");
    fflush(stdout);

    // Create new allocator with expression
    strncpy(new_arg.expr, EXPR, sizeof(new_arg.expr) - 1);
    ioctl_ret = ioctl(root_fd, IOCTL_NEW_EXPR, &new_arg);
    if (ioctl_ret < 0) {
        fprintf(stderr, "ioctl IOCTL_NEW_EXPR failed with errno %d\n", errno);
        return 1;
    }

    printf("OK\n");

    // There should be a new virtual file in our /dev folder now
    // Open it
    snprintf(fname, sizeof(fname), "/dev/%lu_match", new_arg.id);
    fd_match = open(fname, O_RDWR);
    if (fd_match < 0) {
        fprintf(stderr, "Could not open %s - errno %d\n", fname, errno);
        return 1;
    }

    // Read how much memory is available
    if (read(fd_match, &mem_free_pre, sizeof(mem_free_pre)) < 0){
        fprintf(stderr, "read from %s failed with errno %d\n", fname, errno);
        return 1;
    }
    printf("Successfully opened the new allocator instance\n%lu kB of matching memory are available!\n", mem_free_pre >> 10);

    // Map a page
    match_range = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd_match, 0);
    if(match_range == MAP_FAILED){
        fprintf(stderr, "Map matching %lu B failed with errno %d\n", page_size, errno);
        return 1;
    }
    printf("Successfully mapped a page from %s\n", fname);

    // Write to it, hopefully without causing a segfault
    memset(match_range, 0xba, page_size);

    // Check how much memory is still available afterwards
    if (read(fd_match, &mem_free_post, sizeof(mem_free_post)) < 0){
        fprintf(stderr, "read from %s failed with errno %d\n", fname, errno);
        return 1;
    }
    assert(mem_free_post == mem_free_pre - page_size);

    // Verify that page satisfies condition
    paddr = get_physical_address((unsigned long) match_range);
    assert(eval_address(paddr));

    printf("Physical address 0x%lx of the newly alloacted page satisfies our condition.\n", paddr);

    // Unmap
    munmap(match_range, page_size);

    // Close handles
    printf("Closing...\n");
    close(fd_match);
    close(fd_non_match);

    // Delete expression -> frees pre-allocated pages in kernel
    printf("Deleting expression...\n");
    del_arg = new_arg.id;
    ioctl_ret = ioctl(root_fd, IOCTL_DELETE_EXPR, &del_arg);
    if (ioctl_ret < 0) {
        fprintf(stderr, "Ioctl IOCTL_DELETE_EXPR failed with errno %d\n", errno);
    }

    // Close root handle
    close(root_fd);
    printf("All OK\n");
}
