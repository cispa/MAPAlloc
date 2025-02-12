/** 
 * Contains the mmap interface for allocating pages that do not satisfy the expression.
 * The set of satisfying pages should be significantly smaller than the set of non-satisfying pages.
**/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <asm/page.h>
#include "../include/interfaces.h"

ssize_t non_matching_read(struct file *, char __user * data, size_t size, loff_t *) { // TODO
    return -EINVAL;
}

ssize_t non_matching_write(struct file *, const char __user *data, size_t size, loff_t *){
    return -EINVAL;
}

static void release_non_matching_mapping(pmem_mapping mapping) {
    page_list* page_entry;
    struct page* page;

    list_del(&mapping->lhead);
    page_entry = (void*) mapping->pages.lhead.next;
    while(page_entry != (void*) &mapping->pages.lhead) {
        page = pfn_to_page(page_entry->pfn);
        __free_page(page);
        page_entry = (void*) page_entry->lhead.next;
        kfree(page_entry->lhead.prev);
    }
    kfree(mapping);
}

static void release_pool(page_list* pages) {
    page_list* cur = (void*) pages->lhead.next;

    while (cur != (void*) pages) {
        __free_page(pfn_to_page(cur->pfn));
        cur = (void*) cur->lhead.next;
        kfree(cur->lhead.prev);
    }
}

// Our munmap handler
static void non_matching_vma_close_callback(struct vm_area_struct *vma) {
    pprocess_entry pentry;
    pmem_mapping mapping;
    struct alloc_instance* inst = lookup_instance_by_vma(vma);

    if(!inst)
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
    if (mapping->is_matching)
        goto exit;

    // Release it
    release_non_matching_mapping(mapping);
    
exit:
    mutex_unlock(&inst->file_lock);
}
static const struct vm_operations_struct non_matching_vm_ops = { .close = non_matching_vma_close_callback, };

int non_matching_mmap(struct file *file, struct vm_area_struct *vma) {
    struct alloc_instance* inst = lookup_instance_by_file(file);
    page_list pages = {.pfn = 0}, *page_entry = NULL;
    unsigned long size = (vma->vm_end - vma->vm_start), mapped_mem = 0, max_iter = 0x100 * (size >> PAGE_SHIFT), i, pfn;
    pprocess_entry entry;
    pmem_mapping mapping = NULL;
    struct page* page;
    unsigned char* page_ptr;
    int rc = -EINVAL, e;

    if(!inst)
        return -ENOENT;

    INIT_LIST_HEAD(&pages.lhead);

    mutex_lock(&inst->file_lock);

    entry = get_process_entry(inst);

    // We were called by a forked child process that intherited the file descriptor
    if (!entry) {
        if (!shared_open(NULL, NULL))
            goto fail;
        entry = get_process_entry(inst);
        if (!entry)
            goto fail;
    }

    mapping = kmalloc(sizeof(*mapping), GFP_KERNEL);
    if (!mapping)
        goto fail;
    memset(mapping, 0, sizeof(*mapping));

    mapping->id = ++ (entry->mapping_inc);
    mapping->uaddr = vma->vm_start;
    INIT_LIST_HEAD(&mapping->pages.lhead);
    list_add(&mapping->lhead, &entry->mappings);

    for (i = 0; i < max_iter && mapped_mem < size; i++) {
        page_entry = kmalloc(sizeof(*page_entry), GFP_KERNEL);
        if (!page_entry)
            goto fail;

        page = alloc_page(GFP_KERNEL);
        pfn = page_to_pfn(page);
        page_entry->pfn = pfn;

        e = shunting_yard(inst->expr, pfn << PAGE_SHIFT);
        if (e) {
            list_add(&page_entry->lhead, &pages.lhead);
            continue;
        }

        // Zero page
        page_ptr = kmap(page);
        if(!page_ptr)
            goto fail;
        memset(page_ptr, 0, PAGE_SIZE);
        kunmap(page);

        rc = vm_insert_page(vma, vma->vm_start + mapped_mem, page);
        if (rc < 0)
            goto fail; 

        list_add(&page_entry->lhead, &mapping->pages.lhead);
        mapped_mem += PAGE_SIZE;
    }

    mapping->num_pages = size >> PAGE_SHIFT;
    vma->vm_ops = &non_matching_vm_ops;

    release_pool(&pages);
    mutex_unlock(&inst->file_lock);
    return 0;
fail:
    release_non_matching_mapping(mapping);
    release_pool(&pages);
    mutex_unlock(&inst->file_lock);
    if(!rc)
        rc = -EFAULT;
    return rc;
}
