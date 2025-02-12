#ifndef COLOR_ALLOCATOR_H
#define COLOR_ALLOCATOR_H

#define ALLOC_ROOT_FILE_NAME "color_allocator"
#define EXPR_SIZE 256

typedef struct {
    unsigned long addr;
    unsigned long size;
    unsigned long args;
    unsigned long perms;
} mmap_ioctl_arg;

typedef struct {
    // Filled in by user
    char expr[EXPR_SIZE];

    // Filled in by kernel
    unsigned long id;
} ioctl_new_exrp_arg;

typedef ioctl_new_exrp_arg ioctl_read_exrp_arg;
typedef unsigned long ioctl_delete_exrp_arg;

#define CUSTOM_MAP_TYPE 0xc4
#define IOCTL_MAP _IOWR(CUSTOM_MAP_TYPE, 1, mmap_ioctl_arg)
#define IOCTL_LOCK _IO(CUSTOM_MAP_TYPE, 2)

#define ROOT_INTERFACE_TYPE 0xc5
#define IOCTL_NEW_EXPR _IOWR(ROOT_INTERFACE_TYPE, 1, ioctl_new_exrp_arg)
#define IOCTL_READ_EXPR _IOWR(ROOT_INTERFACE_TYPE, 2, ioctl_read_exrp_arg)
#define IOCTL_DELETE_EXPR _IOWR(ROOT_INTERFACE_TYPE, 3,  ioctl_delete_exrp_arg)


#endif