#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"

struct frame
{
   void *page_addr; 
   struct vm_entry *vme;
   struct thread *thread;
   struct list_elem f_elem; 
};

extern struct list frame_table;
extern struct lock frame_lock;
extern struct list_elem *frame_clock; // ㅁㄹ

void frame_table_init(void);
void frame_insert(struct frame *frame);
void frame_delete(struct frame *frame);

void frame_evict(); 
struct frame* frame_alloc(enum palloc_flags flags);
void frame_free(void *addr);

#endif