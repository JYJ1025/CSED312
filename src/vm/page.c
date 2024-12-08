#include "vm/page.h"
#include "vm/frame.h"
#include <string.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "filesys/file.h"

static unsigned vm_hash (const struct hash_elem *e, void *aux);
static bool vm_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);

// SPT 생성 
void vm_init (struct hash *vm) {
	hash_init(vm, vm_hash, vm_less, NULL);
}

static unsigned vm_hash (const struct hash_elem *e, void *aux UNUSED) {
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
	return hash_int((int)vme->vaddr);
}

static bool vm_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
	return hash_entry(a, struct vm_entry, elem)->vaddr < hash_entry(b, struct vm_entry, elem)->vaddr;
}	

// SPT 삭제 
void vm_destroy(struct hash *vm) {
    hash_destroy(vm, vm_destroy_func);
}

void vm_destroy_func(struct hash_elem *e, void *aux UNUSED) {
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
	if (vme->is_loaded) {
		free_frame(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
	}
	free(vme);
}

// SPT 관리 
bool vme_insert (struct hash *vm, struct vm_entry *vme) {	
	if (hash_insert(vm, &vme->elem)) 
		return true;
	else 
		return false;

}

bool vme_delete (struct hash *vm, struct vm_entry *vme) {
	if (hash_delete(vm, &vme->elem)) {
		free_frame(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
		free(vme);
		return true;
	}
	else {
		return false;
	}
}	

// lazy loading 
struct vm_entry *vme_find (void *vaddr) {
	struct hash *vm = &thread_current()->vm;
	struct vm_entry vme;
	struct hash_elem *elem;

	vme.vaddr = pg_round_down(vaddr);

	if ((elem = hash_find(vm, &vme.elem)))
		return hash_entry(elem, struct vm_entry, elem);
	else 
		return NULL;
}

bool load_file (void* addr, struct vm_entry *vme) {
	int byte_read = file_read_at(vme->file, addr, vme->read_bytes, vme->offset);
	if (byte_read != (int)vme->read_bytes)
		return false;

	memset(addr + vme->read_bytes, 0, vme->zero_bytes);
	return true;
}

struct vm_entry *vme_construct ( uint8_t type, void *vaddr, bool writable, bool is_loaded, struct file* file, size_t offset, size_t read_bytes, size_t zero_bytes) {
	struct vm_entry* vme = (struct vm_entry*)malloc(sizeof(struct vm_entry));
      if (!vme) 
        return NULL;
      memset(vme, 0, sizeof(struct vm_entry));

      vme->type = type;
      vme->vaddr = vaddr;
      vme->writable = writable;
      vme->is_loaded = is_loaded;
      vme->file = file;
      vme->offset = offset;
      vme->read_bytes = read_bytes;
      vme->zero_bytes = zero_bytes;

	  return vme;
}