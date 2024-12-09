#include <string.h>
#include "vm/page.h"
#include "vm/frame.h"
// #include "vm/swap.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "filesys/file.h"

#include "userprog/syscall.h"
extern struct lock lock_file;

static unsigned vm_hash(const struct hash_elem *, void *UNUSED);
static bool vm_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static void vm_destroy_func(struct hash_elem *, void *UNUSED);

// static struct list_elem *get_next_lru_clock()
// {
//     if (list_empty(&lru_list))
//     {
//         return NULL;
//     }

//     if (lru_clock && lru_clock != list_end(&lru_list))
//     {   
//         lru_clock = list_next(lru_clock);   
//     } 

//     if (!lru_clock || lru_clock == list_end(&lru_list))
//     {   
//         return (lru_clock = list_begin(&lru_list));   
//     } 
//     else
//     {
//         return lru_clock;
//     }

// }

// SPT 생성/삭제
void vm_init(struct hash *vm) {
    hash_init(vm, vm_hash, vm_less, NULL);
}

static unsigned
vm_hash(const struct hash_elem *e, void *aux UNUSED) {
    struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
    return hash_int((int)vme->vaddr);
}

static bool
vm_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    void *vaddr_a = hash_entry(a, struct vm_entry, elem)->vaddr;
    void *vaddr_b = hash_entry(b, struct vm_entry, elem)->vaddr;
    if(vaddr_a < vaddr_b)
        return true;
    else
        return false;
}

void vm_destroy(struct hash *vm) {
    hash_destroy(vm, vm_destroy_func);
}

static void
vm_destroy_func(struct hash_elem *e, void *aux UNUSED) {
    struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
    if(vme->is_loaded) {
        lock_acquire(&frame_lock);
        frame_free(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
        lock_release(&frame_lock);
    }
    // else{
    //     if(vme->_pin)
    //     {
    //         // swap_free(vme->swap_slot);
    //     }
    // }
    free(vme);
}

// SPT 관리 
bool vme_insert(struct hash *vm, struct vm_entry *vme) {
    if (!hash_insert(vm, &vme->elem))
        return true;
    else
        return false;
}


bool vme_delete(struct hash *vm, struct vm_entry *vme) {
    if (!hash_delete(vm, &vme->elem))
        return false;
    else {
        lock_acquire(&frame_lock);
        frame_free(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
        lock_release(&frame_lock);
        free(vme);
        return true;
    }
}

// lazy loading 
struct vm_entry *find_vme(void *vaddr) {
    struct vm_entry vme;
    struct hash *vm = &thread_current()->vm;
    struct hash_elem *elem;
    vme.vaddr = pg_round_down(vaddr);
    if ((elem = hash_find(vm, &vme.elem))) 
        return hash_entry(elem, struct vm_entry, elem);
    else
        return NULL;
}

bool load_file(void *kaddr, struct vm_entry *vme)
{
    int read_byte = file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset);

    if (read_byte != (int)vme->read_bytes)
        return false;
    memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);

    return true;
}
