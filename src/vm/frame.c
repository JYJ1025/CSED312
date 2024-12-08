#include "vm/frame.h"
#include <list.h>
#include "threads/malloc.h"

extern struct lock file_lock;

struct list frame_table;
struct lock frame_lock;
struct list_elem *frame_clock;

// frame_table 관리 
void frame_table_init(void) {
    list_init(&frame_table);
	lock_init(&frame_lock);
	frame_clock = NULL;
}

void frame_insert(struct frame *frame) {
    lock_acquire(&frame_lock);
    list_push_back(&frame_table, &frame->ft_elem);
    lock_release(&frame_lock);
}

void frame_delete(struct frame *frame) {
    list_remove(&frame->ft_elem);
}

// frame 할당 / 해제
struct frame* alloc_frame(enum palloc_flags flags) {
    struct frame *frame; 

	ASSERT(flags & PAL_USER);
    frame = (struct frame *)malloc(sizeof(struct frame));
	
    if (!frame) return NULL;
    memset(frame, 0, sizeof(struct frame));

    frame->thread = thread_current();
    frame->page_addr = palloc_get_page(flags);
    
    while (!(frame->page_addr))
    {
        // evict_frame();
        frame->page_addr = palloc_get_page(flags); 
    }

	ASSERT(pg_ofs(frame->page_addr) == 0);
	// frame->pinned = false;
	frame_insert(frame);		

    return frame;
    
}

struct frame* frame_find(void* addr) {
    struct list_elem *e;
	for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
	{
		struct frame *frame = list_entry(e, struct frame, ft_elem);
		if ((frame->page_addr) == addr)
		{
			return frame;
		}
	}
	return NULL;
}

void free_frame(void *addr) {
	struct frame *frame = frame_find(addr);
	if (frame) {	
		frame->vme->is_loaded = false;
		pagedir_clear_page(frame->thread->pagedir, frame->vme->vaddr);
		palloc_free_page(frame->page_addr);
		frame_delete(frame);
		free(frame);
	}
}