#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "userprog/syscall.h"

#include "vm/page.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

int fn_to_argument(char **argv, char *file_name);
void argument_stack(char **argv, int argc, void **esp);
struct thread *get_child_process (pid_t pid);\
//Project 3
void remove_child_process(struct thread *cp);

int process_add_file (struct file *f);
struct file *process_get_file(int fd);
void process_close_file(int fd);
//Project 3
bool verify_stack(uint32_t addr, void *esp);
bool expand_stack(void* addr);

bool handle_mm_fault(struct vm_entry *vme);

#endif /* userprog/process.h */