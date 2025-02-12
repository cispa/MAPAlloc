#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "color_allocator.h"

int main(int argc, char* argv[]) {
    ioctl_new_exrp_arg arg = {};
    int fd, ret;

    if (argc != 2) {
        printf("Usage: %s \"<expression>\"\n", argv[0]);
        printf("Example: %s \"(x >> 12) & 31 == 0\"\n", argv[0]);
        return 1;
    }

    strncpy(arg.expr, argv[1], sizeof(arg.expr));

    fd = open("/dev/" ALLOC_ROOT_FILE_NAME, O_RDWR);
    if (fd < 0) {
        if (errno == ENOENT)
            fprintf(stderr, "/dev/" ALLOC_ROOT_FILE_NAME " does not exist. Make sure that you have loaded the kernel module!\n");
        else 
            fprintf(stderr, "Cannot open /dev/" ALLOC_ROOT_FILE_NAME "! Errno: %d\n", errno);
        return -1;

    }

    ret = ioctl(fd, IOCTL_NEW_EXPR, &arg);
    close(fd);

    if (ret < 0){
        fprintf(stderr, "Cannot add new expression! Errno: %d\n", errno);
        return 1;
    }

    printf("Added expression \"%s\" with ID %lu!\nInterfaces should be located under '/dev/%lu_match' and '/dev/%lu_non_match'\n", argv[1], arg.id, arg.id, arg.id);

    return 0;
}
