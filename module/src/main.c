#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/cred.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <asm/page.h>
#include "../include/interfaces.h"
#include "../include/set_kernel_arguments.h"

MODULE_LICENSE("GPL");
MODULE_VERSION("1.6");

#define FLAG_INVERSE_MATCHING (1ul << 49)

static unsigned int instance_counter = 0;
struct device* root_chardev = NULL;
struct class* root_cls = NULL;
struct cdev root_cdev;
static int root_major = -1;
static struct kprobe mmap_probe;

static DEFINE_XARRAY(monitored_pids);
static LIST_HEAD(instances);
static struct mutex instance_lock;

static int shared_close(struct inode *inode, struct file *file);
static long shared_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

static struct file_operations fops_priv = {
    .open = shared_open,
    .release = shared_close,
    .read = matching_read,
    .write = matching_write,
    .mmap = matching_mmap,
    .unlocked_ioctl = shared_ioctl,
    .compat_ioctl = compat_ptr_ioctl,
};

static struct file_operations fops_unpriv = {
    .open = shared_open,
    .release = shared_close,
    .read = non_matching_read,
    .write = non_matching_write,
    .mmap = non_matching_mmap,
    .unlocked_ioctl = shared_ioctl,
    .compat_ioctl = compat_ptr_ioctl,
};

static int _set_close_on_exec(const struct file* f) {
    struct files_struct *files = current->files;
    struct fdtable *fdt;
    unsigned int i;

    if (!files)
        return -1;
    
    fdt = files_fdtable(files);

    for (i = 0; i < fdt->max_fds; i++) {
        if (fdt->fd[i] == f) {
            __set_bit(i, fdt->close_on_exec);
            return 0;
        }
    }

    return -1;
}

static void* get_protection_entry(void) {
    void* entry = NULL;

    struct task_struct* t = current;
    // TODO - find out whether this can be done with t->flags for performance
    while (t && t->pid > 1) {
        entry = xa_load(&monitored_pids, (unsigned long) t->pid);
        if (entry)
            break;
        t = t->real_parent;
    }

    return entry;
}

// Force certain processes to use our allocator
static int mmap_handler_pre(struct kprobe *p, struct pt_regs *regs) {
    struct files_struct* files;
    struct fdtable *fdt;
    struct file* f;
    void* entry;
    unsigned long expr_number, i;
    // unsigned long flag;
    unsigned char matching;
    int fd;
    char fname[64];

    // Check whether the process, or one of its parents, was marked
    entry = get_protection_entry();
    if(!entry)
        return 0;
    
    // For now, allow file-based allocations without restrictions
    if (regs_get_kernel_argument(regs, 0) != 0)
        return 0;
    
    expr_number = xa_to_value(entry);
    matching = (expr_number & FLAG_INVERSE_MATCHING) ? 0 : 1;
    expr_number &= ~FLAG_INVERSE_MATCHING;
    
    // Check whether file is open
    files = current->files;
    fdt = files_fdtable(files);
    for (i = 0; i < fdt->max_fds; i++){
        f = fdt->fd[i];
        if (!f)
            continue;
        if ((matching && f->f_op->mmap == matching_mmap) || (!matching && f->f_op->mmap == non_matching_mmap)) {
            // The file is open, so we can use it
            // flag = regs_get_kernel_argument(regs, 4); // flag
            regs_set_kernel_argument(regs, 0, (__UINTPTR_TYPE__) f); // file <- f
            // regs_set_kernel_argument(regs, 4, flag & ~MAP_ANONYMOUS); // clear MAP_ANONYMOUS if set
            return 0;
        }
    }

    // We need to open a new handle
    snprintf(fname, sizeof(fname), matching ? "/dev/%ld_match" : "/dev/%ld_non_match", expr_number);
    f = filp_open(fname, O_RDWR, 0);
    if (IS_ERR(f)) {
        printk(KERN_ERR "filp_open failed: %ld\n", PTR_ERR(f));
        goto fail;
    }
    fd = get_unused_fd_flags(O_RDWR);
    if (fd < 0) {
        printk(KERN_ERR "fdf: %d\n", -fd);
        filp_close(f, NULL);
        goto fail;
    }
    fd_install(fd, f);
    _set_close_on_exec(f);

    regs_set_kernel_argument(regs, 0, (__UINTPTR_TYPE__) f);
    return 0;
fail:
    regs_set_kernel_argument(regs, 2, 0); // Don't allocate anything -> likely crashes the user program
    return 0;
}

pprocess_entry get_process_entry(struct alloc_instance* inst) {
    pprocess_entry entry;

    for (entry = (void*) inst->process_entries.next; entry != (void*) &inst->process_entries; entry = (void*) entry->lhead.next) {
        if(entry->pid  == current->pid)
            return entry;
    }

    return NULL;
}

static struct alloc_instance* lookup_instance_by_id (unsigned long id) {
    struct alloc_instance* cur = (void*) instances.next;

    while (cur != (void*) &instances){
        if (cur->id == id)
            return cur;
        cur = (void*) cur->lhead.next;
    }

    return NULL;
}

static struct alloc_instance* lookup_instance_by_id_locked (unsigned long id) {
    struct alloc_instance* ret;

    mutex_lock(&instance_lock);
    ret = lookup_instance_by_id(id);
    mutex_unlock(&instance_lock);

    return ret;
}

struct alloc_instance* lookup_instance_by_file (const struct file* f) {
    unsigned long id;

    if(!f)
        return NULL;
    if(!f->f_path.dentry)
        return NULL;
    if(!f->f_path.dentry->d_name.name)
        return NULL;
    if (sscanf(f->f_path.dentry->d_name.name, "%lu_", &id) != 1)
        return NULL;
    
    return lookup_instance_by_id_locked(id);
}

struct alloc_instance* lookup_instance_by_vma (const struct vm_area_struct* vma) {
    struct alloc_instance* cur, *rc = NULL;
    pprocess_entry entry;
    pmem_mapping mapping;

    mutex_lock(&instance_lock);

    for (cur = (void*) instances.next; cur != (void*) &instances; cur = (void*) cur->lhead.next) {
        entry = get_process_entry(cur);
        if (!entry)
            continue;
        for (mapping = (void*) entry->mappings.next; mapping != (void*) & entry->mappings; mapping = (void*) mapping->lhead.next) {
            if (mapping->uaddr == vma->vm_start)
                exit_return(cur);
        }
    }

exit:
    mutex_unlock(&instance_lock);
    return rc;
}

static void release_process(struct alloc_instance* inst, pprocess_entry restrict entry) {
    page_list* page_list_entry, *next;
    pmem_mapping mapping;

    mapping = (void*) entry->mappings.next;
    while (mapping != (void*) &entry->mappings) {
        if (!(current->flags & PF_EXITING))
            vm_munmap(mapping->uaddr, mapping->num_pages * PAGE_SIZE);

        page_list_entry = (void*) mapping->pages.lhead.next;
        while (page_list_entry != (void*) &mapping->pages.lhead) {
            next = (void*) page_list_entry->lhead.next;
            if (mapping->is_matching)
                list_add(&page_list_entry->lhead, &inst->valid_pages.lhead);
            else 
                __free_page(pfn_to_page(page_list_entry->pfn));
            page_list_entry = next;
        }

        mapping = (void*) mapping->lhead.next;
        kfree(mapping->lhead.prev);
    }
    list_del(&entry->lhead);
    kfree(entry);
}

static int shared_close(struct inode *inode, struct file *file) {
    pprocess_entry entry;
    struct alloc_instance* inst = lookup_instance_by_file(file);
    unsigned char is_matching = strstr(file->f_path.dentry->d_name.name, "non_match") == NULL ? 1 : 0;

    if (!inst)
        return -ENOENT;

    mutex_lock(&inst->file_lock);

    entry = get_process_entry(inst);
    if (!entry)
        goto exit;

    if (is_matching)
        entry->is_matching_open = 0;
    else
        entry->is_non_matching_open = 0;
    
    if (entry->is_matching_open || entry->is_non_matching_open)
        goto exit;
    
    release_process(inst, entry);

exit:
    mutex_unlock(&inst->file_lock);
    return 0;
}

int shared_open(struct inode *const inode, struct file *file) {
    int rc = -ENOMEM;
    pprocess_entry entry;
    struct alloc_instance* inst = lookup_instance_by_file(file);
    unsigned char is_matching = strstr(file->f_path.dentry->d_name.name, "non_match") == NULL ? 1 : 0;

    if (!inst)
        return -ENOENT;
    
    if(inode)
        mutex_lock(&inst->file_lock);
    entry = get_process_entry(inst);

    if (entry) {
        // Only allow one handle per process
        if (is_matching && entry->is_matching_open)
            exit_return(-EEXIST);
        if (!is_matching && entry->is_non_matching_open)
            exit_return(-EEXIST);
        
        entry->is_matching_open = entry->is_non_matching_open = 1;
        rc = 0;
        goto exit;
    }
    
    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        goto exit;
    memset(entry, 0, sizeof(*entry));
    
    entry->mapping_inc = 1;
    entry->pid = current->pid;
    if (is_matching)
        entry->is_matching_open = 1;
    else
        entry->is_non_matching_open = 1;

    INIT_LIST_HEAD(&entry->mappings);
    list_add(&entry->lhead, &inst->process_entries);

    rc = 0;
exit:
    if(inode)
        mutex_unlock(&inst->file_lock);

    return rc;
}

// Provide mmap as an ioctl interface as well
static long shared_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    mmap_ioctl_arg user_arg;
    struct alloc_instance* inst;
    unsigned long addr;
    unsigned char matching;
    void* entry;
    
    if (cmd == IOCTL_LOCK) {
        matching = file->f_op->mmap == matching_mmap ? 1 : 0;
        entry = get_protection_entry();
        if (entry)
            return -EEXIST;
        inst = lookup_instance_by_file(file);
        if (!inst)
            return -EINVAL;
        if (_set_close_on_exec(file) < 0)
            return -EFAULT;
        
        xa_store(&monitored_pids, current->pid, xa_mk_value(inst->id | (matching ? 0 : FLAG_INVERSE_MATCHING)), GFP_KERNEL);
        return 0;
    }

    if (cmd == IOCTL_MAP) {
        if(file->f_op->mmap != matching_mmap && file->f_op->mmap != non_matching_mmap)
            return -EPERM;

        if (copy_from_user(&user_arg, (void* __user) arg, sizeof(user_arg)) != 0)
            return -EFAULT;
        
        addr = vm_mmap(file, user_arg.addr, user_arg.size, user_arg.perms, user_arg.args, 0);
        if (!~addr)
            return -EFAULT;
        
        if (copy_to_user((void* __user) arg, &addr, sizeof(addr)) != 0)
            return -EFAULT;
        return 0;
    }
    
    return -ENOTTY;
}

static int create_chardev(int* major, struct class ** cls, struct device ** chardev, struct cdev* cdev, const struct file_operations* fops, const char* name) {
    if (alloc_chrdev_region(major, 0, 1, name) < 0) {
        printk(KERN_ALERT "Example failed to register a major number\n");
        return *major;
    }

    // Register the device class
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0) 
    *cls = class_create(name);
    #else 
    *cls = class_create(THIS_MODULE, name); 
    #endif 

    if (IS_ERR(*cls)) {
        unregister_chrdev_region(*major, 1);
        printk(KERN_ALERT "Failed to register device class\n");
        return -1;
    }

    *chardev = device_create(*cls, NULL, *major, NULL, name);
    if (IS_ERR(*chardev )) {
        class_destroy(*cls);
        unregister_chrdev_region(*major, 1);
        return -1;
    }

    cdev_init(cdev, fops);
    if (cdev_add(cdev, *major, 1) < 0) {
        device_destroy(*cls, *major);
        class_destroy(*cls);
        unregister_chrdev_region(*major, 1);
        printk(KERN_ALERT "Failed to add cdev\n");
        return -1;
    }
    
    return 0;
}

static void remove_chardev(int major, struct class* cls, struct cdev* cdev, const char* name) {
    cdev_del(cdev);
    device_destroy(cls, major);
    class_destroy(cls);
    unregister_chrdev_region(major, 1);
}


// Dummy
static int root_open(struct inode *inode, struct file *file) {
    return 0;
}

// Dummy
static int root_close(struct inode *inode, struct file *file) {
    return 0;
}

// return id on success, ~0ul otherwise
static unsigned long new_instance (const char* expr) {
    int ret;
    struct alloc_instance* inst;

    printk(KERN_INFO "Starting with expression %s\n", expr);

    inst = kmalloc(sizeof(*inst), GFP_KERNEL);
    if (!inst)
        return ~0ul;
    
    memset(inst, 0, sizeof(*inst));
    
    INIT_LIST_HEAD(&inst->lhead);
    INIT_LIST_HEAD(&inst->process_entries);
    INIT_LIST_HEAD(&inst->valid_pages.lhead);
    mutex_init(&inst->file_lock);
    strncpy(inst->expr, expr, sizeof(inst->expr) - 1);
    inst->id = ++instance_counter;

    search_matching_pages(inst);

    snprintf(inst->fname_match, sizeof(inst->fname_match) - 1, "%lu_match", inst->id);
    ret = create_chardev(&inst->major_match, &inst->cls_match, &inst->chardev_match, &inst->cdev_match, &fops_priv, inst->fname_match);
    if (ret < 0)
        goto fail;

    snprintf(inst->fname_non_match, sizeof(inst->fname_non_match) - 1, "%lu_non_match", inst->id);
    ret = create_chardev(&inst->major_non_match, &inst->cls_non_match, &inst->chardev_non_match, &inst->cdev_non_match, &fops_unpriv, inst->fname_non_match);
    if (ret < 0)
        goto fail;

    list_add(&inst->lhead, &instances);
    
    return inst->id;

fail:
    if (inst->chardev_match) {
        snprintf(inst->fname_match, sizeof(inst->fname_match) - 1, "%lu_match", inst->id);
        remove_chardev(inst->major_match, inst->cls_match, &inst->cdev_match, inst->fname_match);
    }
    if(inst->valid_pages_mem)
        kvfree(inst->valid_pages_mem);
    if (inst->id) {
        free_matching_pages(inst);
        mutex_destroy(&inst->file_lock);
        kfree(inst);
    }

    return ~0ul;
}

static void delete_instance(struct alloc_instance* inst) {
    pprocess_entry entry;

    list_del(&inst->lhead);

    remove_chardev(inst->major_match, inst->cls_match, &inst->cdev_match, inst->fname_match);
    remove_chardev(inst->major_non_match, inst->cls_non_match, &inst->cdev_non_match, inst->fname_non_match);


    entry =  (void*) inst->process_entries.next;
    while(entry != (void*)&inst->process_entries){
        entry = (void*) entry->lhead.next;
        release_process(inst, (void*) entry->lhead.prev);
    }

    free_matching_pages(inst);

    mutex_destroy(&inst->file_lock);

    kfree(inst);
}

// 0 on success, -errno on fail
static long delete_instance_by_id (unsigned long id) {
    struct alloc_instance* inst = lookup_instance_by_id(id);

    if(!inst)
        return -ENOENT;
    
    delete_instance(inst);
    return 0;
}

static unsigned long opcode_arg_size(unsigned int opcode) {
    switch (opcode) {
        case IOCTL_NEW_EXPR:
            return sizeof(ioctl_new_exrp_arg);
        case IOCTL_READ_EXPR:
            return sizeof(ioctl_read_exrp_arg);
        case IOCTL_DELETE_EXPR:
            return sizeof(ioctl_delete_exrp_arg);
        default:;
    }

    return 0;
}

static long root_ioctl(struct file *, unsigned int cmd, unsigned long arg) {
    long rc;
    union {
        ioctl_new_exrp_arg new;
        ioctl_read_exrp_arg read;
        ioctl_delete_exrp_arg delete;
    } user_arg;

    mutex_lock(&instance_lock);

    // Copy user arg over
    if (copy_from_user(&user_arg, (void* __user) arg, opcode_arg_size(cmd)) != 0)
        exit_return(-EFAULT);

    switch (cmd) {
        case IOCTL_NEW_EXPR:
            user_arg.new.id = new_instance(user_arg.new.expr);
            if (!~user_arg.new.id)
                exit_return(-EINVAL);
            if (copy_to_user((void* __user) arg, &user_arg, sizeof(user_arg.new)) != 0)
                exit_return(-EFAULT);
            exit_return(0);
        case IOCTL_READ_EXPR: // TODO
            break;
        case IOCTL_DELETE_EXPR:
            exit_return(delete_instance_by_id(user_arg.delete));
        default:;
    }

    rc = -ENOTTY;
exit:
    mutex_unlock(&instance_lock);
    return rc;
}

static ssize_t root_read(struct file*, char*, size_t, loff_t*) {
    return -ENODEV;
}
static ssize_t root_write(struct file*, const char*, size_t, loff_t*) {
    return -ENODEV;
}

static struct file_operations fops_root = {
    .open = root_open,
    .release = root_close,
    .read = root_read,
    .write = root_write,
    .unlocked_ioctl = root_ioctl,
    .compat_ioctl = compat_ptr_ioctl,
};

static int __init phys_addr_constraint_init(void) {
    memset(&mmap_probe, 0, sizeof(mmap_probe));
    mmap_probe.symbol_name = "vm_mmap_pgoff";
    mmap_probe.pre_handler = mmap_handler_pre;

    if (register_kprobe(&mmap_probe) < 0) {
        printk(KERN_ERR "Could not register kprobe\n");
        return -EFAULT;
    }

    mutex_init(&instance_lock);
    INIT_LIST_HEAD(&instances);
    return create_chardev(&root_major, &root_cls, &root_chardev, &root_cdev, &fops_root, ALLOC_ROOT_FILE_NAME);
}

static void __exit phys_addr_constraint_exit(void) {
    struct alloc_instance* inst = (void*) instances.next;

    while (inst != (void*)&instances) {
        inst = (void*) inst->lhead.next;
        delete_instance((void*) inst->lhead.prev);
    }

    remove_chardev(root_major, root_cls, &root_cdev, ALLOC_ROOT_FILE_NAME);
    mutex_destroy(&instance_lock);
    unregister_kprobe(&mmap_probe);

    pr_info("Interfaces unregistered and module unloaded - Goodbye\n");
}

module_init(phys_addr_constraint_init);
module_exit(phys_addr_constraint_exit);
