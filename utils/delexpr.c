#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "color_allocator.h"

int main(int argc, char* argv[]) {
    ioctl_delete_exrp_arg arg;
    char fname[64];
    int fd, ret;

    if (argc != 2) {
        printf("Usage: %s \"<ID>\"\n", argv[0]);
        printf("Example: %s 6\n", argv[0]);
        return 1;
    }

    arg = atol(argv[1]);
    if (!arg) {
        fprintf(stderr, "Error: '%s' is an invalid number!\n", argv[1]);
        return 1;
    }

    snprintf(fname, sizeof(fname), "/dev/%lu_match", arg);
    if (access(fname, F_OK) != 0) {
        fprintf(stderr, "Error: ID %lu does not exist!\n", arg);
        return 1;
    }

    fd = open("/dev/" ALLOC_ROOT_FILE_NAME, O_RDWR);
    if (fd < 0) {
        if (errno == ENOENT)
            fprintf(stderr, "/dev/" ALLOC_ROOT_FILE_NAME " does not exist. Make sure that you have loaded the kernel module!\n");
        else 
            fprintf(stderr, "Cannot open /dev/" ALLOC_ROOT_FILE_NAME "! Errno: %d\n", errno);
        return -1;

    }

    ret = ioctl(fd, IOCTL_DELETE_EXPR, &arg);
    close(fd);
    
    if (ret < 0){
        fprintf(stderr, "Error: Cannot delete expression! Errno: %d\n", errno);
        return 1;
    }

    printf("Deleted expression with ID %lu!\n", arg);

    return 0;
}
