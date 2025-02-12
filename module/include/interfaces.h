#ifndef INTERFACES_H
#define INTERFACES_H
#include <linux/list.h>
#include <linux/ioctl.h>
#include <linux/xarray.h>
#include <linux/cdev.h>

#include "color_allocator.h"

#define exit_return(ret) do {rc = ret; goto exit;} while(0);

typedef struct {
    struct list_head lhead;
    unsigned long pfn;
} page_list;

typedef struct {
    struct list_head lhead;
    page_list pages;
    unsigned int num_pages;
    unsigned long uaddr;
    unsigned long id;
    unsigned char is_matching : 1;
} mem_mapping, *pmem_mapping;

typedef struct {
    struct list_head lhead;
    struct list_head mappings;
    unsigned long mapping_inc;
    pid_t pid;
    unsigned char is_matching_open : 1;
    unsigned char is_non_matching_open : 1;
} process_entry, *pprocess_entry;

struct alloc_instance {
    struct list_head lhead;
    unsigned long id;

    // For the /dev file
    struct device* chardev_match;
    struct device* chardev_non_match;
    struct class *cls_match;
    struct class *cls_non_match;
    struct cdev cdev_match;
    struct cdev cdev_non_match;
    char fname_match[64];
    char fname_non_match[64];
    int major_match;
    int major_non_match;

    // File-specific lock
    struct mutex file_lock;

    struct list_head process_entries;

    page_list valid_pages;
    void* valid_pages_mem;
    unsigned long num_valid_pages;

    char expr[EXPR_SIZE];
};

int shared_open(struct inode *inode, struct file *file);

unsigned long shunting_yard(const char *expression, unsigned long x_value);

void search_matching_pages(struct alloc_instance*);
void free_matching_pages(struct alloc_instance*);
ssize_t matching_read(struct file *, char __user * data, size_t size, loff_t *);
ssize_t matching_write(struct file *, const char __user *data, size_t size, loff_t *);
int matching_mmap(struct file *file, struct vm_area_struct *vma);

ssize_t non_matching_read(struct file *, char __user * data, size_t size, loff_t *);
ssize_t non_matching_write(struct file *, const char __user *data, size_t size, loff_t *);
int non_matching_mmap(struct file *file, struct vm_area_struct *vma);

pprocess_entry get_process_entry(struct alloc_instance*);
struct alloc_instance* lookup_instance_by_file (const struct file* f);
struct alloc_instance* lookup_instance_by_vma (const struct vm_area_struct* vma);

#endif
