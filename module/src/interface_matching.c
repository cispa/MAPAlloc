/** 
 * Contains the mmap interface for allocating pages that satisfy the expression.
 * The set of satisfying pages should be significantly smaller than the set of non-satisfying pages.
**/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <asm/page.h>
#include "../include/interfaces.h"

#define min_c(x, y) ((x) < (y) ? (x) : (y))
#define SEARCH_MAX ((16ull << 30) >> PAGE_SHIFT)

void search_matching_pages(struct alloc_instance* inst) {
    unsigned long max_iter = SEARCH_MAX;
    struct {
        struct list_head lhead;
        struct page* page;
    } pages = {.page = NULL}, *page_entry = NULL;
    struct sysinfo mem_info;
    page_list* pl_entries;
    unsigned long cur_pfn, size_allocated = 0, i;
    struct page* cur_page;
    int e;

    INIT_LIST_HEAD(&pages.lhead);
    si_meminfo(&mem_info);

    // Stop allocating memory at some point to not trigger the OOM killer
    // Going over 7/8 of the system's free pages, and at most 16 GB
    max_iter = min_c(max_iter, (((mem_info.freeram << PAGE_SHIFT) >> 3) * 7) >> PAGE_SHIFT);

    // Allocate memory for page list
    inst->valid_pages_mem = vmalloc(max_iter * sizeof(inst->valid_pages));
    if(!inst->valid_pages_mem) {
        printk(KERN_ERR "Could not search for valid pages - out of memory!\n");
        return;
    }
    pl_entries = (void*)inst->valid_pages_mem;

    // Get many pages from allocator, reserve those which match our condition
    for (i = 0; i < max_iter; i++) {
        cur_page = alloc_page(GFP_KERNEL);
        if (!cur_page)
            break;
        
        page_entry = kmalloc(sizeof(*page_entry), GFP_KERNEL);
        if (!page_entry) {
            __free_page(cur_page);
            break;
        }

        cur_pfn = page_to_pfn(cur_page);
        e = shunting_yard(inst->expr, cur_pfn << PAGE_SHIFT);
        // We want this page
        if (e) {
            SetPageReserved(cur_page);
            pl_entries[inst->num_valid_pages].pfn = cur_pfn;
            list_add(&(pl_entries[inst->num_valid_pages].lhead), &inst->valid_pages.lhead);
            size_allocated += PAGE_SIZE;
            inst->num_valid_pages++;
            continue;
        }

        // We don't want this page
        // Keep it allocated for now, until we have found enough pages that satisfy our condition
        page_entry->page = cur_page;
        list_add(&page_entry->lhead, &pages.lhead);
    }

    // Now free falsifying pages we kept allocated
    page_entry = (void*) pages.lhead.next;
    while (page_entry != (void*)&pages) {
        __free_page(page_entry->page);
        page_entry = (void*) page_entry->lhead.next;
        kfree(page_entry->lhead.prev);
    }

    printk(KERN_INFO "Pre-allocated %lu/%lu matching pages (%lu kB / %lu kB), when %lu kB are free\n", size_allocated >> PAGE_SHIFT, i, size_allocated >> 10, i << (PAGE_SHIFT - 10), mem_info.freeram << (PAGE_SHIFT - 10));
}

void free_matching_pages(struct alloc_instance* inst) {
    struct page* page;
    unsigned long i;
    page_list* pl_entry = (void*) inst->valid_pages_mem;


    for(i = 0; i < inst->num_valid_pages; i++){
        page = pfn_to_page(pl_entry[i].pfn);
        ClearPageReserved(page);
        __free_page(page);
    }
    
    kvfree(inst->valid_pages_mem);
}
  
// Our munmap handler
static void matching_vma_close_callback(struct vm_area_struct *vma) {
    struct alloc_instance* inst = lookup_instance_by_vma(vma);
    pprocess_entry pentry;
    pmem_mapping mapping;
    page_list* page_entry, *next;

    if (!inst)
        return;
    
    mutex_lock(&inst->file_lock);

    pentry = get_process_entry(inst);
    if (!pentry)
        goto exit;

    // Find the mapping we are releasing
    for (mapping = (void*) pentry->mappings.next; mapping != (void*) &pentry->mappings; mapping = (void*) mapping->lhead.next) {
        if (mapping->uaddr == vma->vm_start)
            break;
    }
    if (mapping->uaddr != vma->vm_start)
        goto exit;
    if (!mapping->is_matching)
        goto exit;

    // Release it
    list_del(&mapping->lhead);
    page_entry = (void*) mapping->pages.lhead.next;
    while(page_entry != (void*) &mapping->pages.lhead) {
        next = (void*) page_entry->lhead.next;
        list_add(&page_entry->lhead, &inst->valid_pages.lhead);
        page_entry = next;
    }
    kfree(mapping);
    
exit:
    mutex_unlock(&inst->file_lock);
}
static const struct vm_operations_struct matching_vm_ops = { .close = matching_vma_close_callback, };

// Return the amount of matching memory that is still free
ssize_t matching_read(struct file * f, char __user * data, size_t size, loff_t *) {
    struct alloc_instance* inst = lookup_instance_by_file(f);
    page_list* pl_entry;
    unsigned long mem_free = 0;

    if (!inst)
        return -ENOENT;

    if (size != sizeof(mem_free))
        return -EINVAL;

    mutex_lock(&inst->file_lock);

    for (pl_entry = (void*) inst->valid_pages.lhead.next; pl_entry != (void*) &inst->valid_pages; pl_entry = (void*) pl_entry->lhead.next)
        mem_free += PAGE_SIZE;

    mutex_unlock(&inst->file_lock);

    return copy_to_user(data, &mem_free, sizeof(mem_free));
}

ssize_t matching_write(struct file *, const char __user *data, size_t size, loff_t *){
    return -EINVAL;
}

int matching_mmap(struct file *file, struct vm_area_struct *vma) {
    struct alloc_instance* inst = lookup_instance_by_file(file);
    unsigned long size = (vma->vm_end - vma->vm_start), mapped_mem = 0;
    pprocess_entry entry;
    page_list* page_list_entry, *next;
    struct page* page;
    void* page_ptr;
    pmem_mapping mapping = NULL;
    int rc = -EINVAL;

    if(!inst)
        return -ENOENT;

    mutex_lock(&inst->file_lock);

    entry = get_process_entry(inst);

    // We were called by a forked child process that intherited the file descriptor
    if (!entry) {
        if (!shared_open(NULL, file))
            goto fail;
        entry = get_process_entry(inst);
        if (!entry)
            goto fail;
    }

    mapping = kmalloc(sizeof(*mapping), GFP_KERNEL);
    if (!mapping)
        goto fail;
    memset(mapping, 0, sizeof(*mapping));

    INIT_LIST_HEAD(&mapping->pages.lhead);
    mapping->id = ++ (entry->mapping_inc);
    mapping->uaddr = vma->vm_start;
    mapping->is_matching = 1;

    page_list_entry = (void*) inst->valid_pages.lhead.next;

    while (page_list_entry != (void*) &inst->valid_pages) {
        if (mapped_mem >= size)
            break;

        page = pfn_to_page(page_list_entry->pfn);

        // Zero page
        page_ptr = kmap(page);
        if(!page_ptr)
            goto fail;
        memset(page_ptr, 0, PAGE_SIZE);
        kunmap(page);

        rc = vm_insert_page(vma, vma->vm_start + mapped_mem, page);
        if (rc < 0)
            goto fail;
        
        // printk(KERN_INFO "Mapped page @ %lx - %lx\n", index << PAGE_SHIFT, page_to_pfn(page));


        next = (void*) page_list_entry->lhead.next;
        list_del(&page_list_entry->lhead);
        list_add(&page_list_entry->lhead, &mapping->pages.lhead);
        page_list_entry = next;
        mapped_mem += PAGE_SIZE;
    }

    mapping->num_pages = size >> PAGE_SHIFT;
    list_add(&mapping->lhead, &entry->mappings);
    vma->vm_ops = &matching_vm_ops;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0) 
    vm_flags_set(vma, VM_SHARED | VM_MAYWRITE);
#else 
    vma->vm_flags |= VM_SHARED | VM_MAYWRITE;
#endif 
    
    mutex_unlock(&inst->file_lock);
    return 0;
fail:
    mutex_unlock(&inst->file_lock);
    if(mapping)
        kfree(mapping);
    return rc;
}

