#include "vm/frame.h"
#include <list.h>
#include "vm/page.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"

struct list frame_table;
struct lock frame_lock;
struct list_elem *frame_clock;

extern struct lock file_lock;

// frame table 관리 
void frame_table_init(void) {
  list_init(&frame_table);
  lock_init(&frame_lock);
  frame_clock = NULL;
}

void frame_insert(struct frame *frame) {
  list_push_back(&frame_table, &frame->f_elem);
}

void frame_delete(struct frame *frame) {
  if (frame_clock == &frame->f_elem)
  {
    frame_clock = list_remove(frame_clock);
  }
  else
  {
    list_remove(&frame->f_elem);
  }
}

// frame table alloc/free
struct frame* frame_alloc(enum palloc_flags flags)
{
    ASSERT(flags & PAL_USER);
    // if((flags & PAL_USER) == 0){
    //     return NULL;
    // }
    struct frame* frame = (struct frame *)malloc(sizeof(struct frame));
    memset(frame, 0, sizeof(struct page));
    frame->thread = thread_current();
    frame->page_addr = palloc_get_page(flags);
    
    if (!frame) {
        palloc_free_page(frame->page_addr);
        return NULL;
    }

    while (!frame->page_addr) {
        frame_evict();
        frame->page_addr=palloc_get_page(flags);
    }

    // ASSERT(pg_ofs(frame->page_addr) == 0); // ㅁㄹ
    frame_insert(frame);

    return frame;
}

void frame_evict() {
    struct frame *frame;
    bool dirty = pagedir_is_dirty(frame->thread->pagedir, frame->vme->vaddr);

    if (frame->vme->type == VM_FILE && dirty) {
        // lock_acquire(&file_lock); ㅁㄹ
        file_write_at(frame->vme->file, frame->page_addr, frame->vme->read_bytes, frame->vme->offset);
        // lock_release(&file_lock); ㅁㄹ
    }
    else if (frame->vme->type == VM_BIN && dirty) {
        frame->vme->type = VM_ANON; // -> 이게 예외처리임 ㅁㄹ
    }

    frame->vme->is_loaded = false;
    pagedir_clear_page(frame->thread->pagedir, frame->vme->vaddr);
    frame_delete(frame);
    palloc_free_page(frame->page_addr);
    free(frame);

    return;
}


void frame_free(void *kaddr)
{
    struct frame *frame;

    for (struct list_elem *element = list_begin(&frame_table); element != list_end(&frame_table); element = list_next(element))
    {
        frame = list_entry(element, struct frame, f_elem);
        if (frame->page_addr == kaddr) {
            if (frame != NULL) {
                pagedir_clear_page(frame->thread->pagedir, frame->vme->vaddr);
                frame_delete(frame);
                palloc_free_page(frame->page_addr);
                free(frame);
            }
            break;
        }
    }
}