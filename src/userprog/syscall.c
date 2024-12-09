#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler(struct intr_frame *);
struct lock file_lock;

void valid_access(void *addr)
{
  if (addr >= (void *)0xc0000000 || addr < (void *)0x08048000 ) 
  {
    sys_exit(-1); // 커널 메모리 범위 접근 시 종료
  }
}


void get_argument(void *esp, void **arg, int count) {
  uint32_t stack_start = 0xC0000000;
  uint32_t stack_limit = 0x8000000;
  
  for (int i = 0; i < count; i++) {
    
    valid_access((esp + 4 * i));

    if (!vme_find((esp + 4 * i))) {
        uint32_t addr_u32 = (uint32_t)(esp + 4 * i);
        uint32_t esp_u32 = (uint32_t)esp;

        if (addr_u32 >= stack_start || addr_u32 < stack_start - stack_limit || addr_u32 < esp_u32 - 32) {
            sys_exit(-1); // 스택 확장이 불가능한 경우 종료
        }

        // 4. 스택 확장 (expand_stack)
        if (!expand_stack(esp + 4 * i)) {
            sys_exit(-1); // 스택 확장 실패 시 종료
        }
    }

    arg[i] = *(void **)(esp + 4 * i);
  }
}

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

void sys_halt(void)
{
  shutdown_power_off();
}

void sys_exit(int status)
{
  struct thread *t  = thread_current();
  t->exit_code = status;
  printf("%s: exit(%d)\n", t->name, status);
  thread_exit();
}

pid_t sys_exec(const char *cmd_line)
{
  struct thread *child;
  // if(!valid_access(cmd_line)) {
  //   sys_exit(-1);
  // }
  valid_access(cmd_line);
  // 새로운 child process 생성 
  pid_t pid = process_execute(cmd_line); 
  // process 생성에 실패한 경우
  if (pid == -1) return -1;
  // child에 current thread의 child process를 저장 (pid가 일치하는지 확인)
  child = get_child_process(pid);
  // process execute에서 start_process 실행 시 sema_up 실행 (child process가 load 될때까지 대기)
  sema_down(&(child->exec_semaphore));
  if (!child->is_load) {
    return -1;
  }
  return pid;
}

int sys_wait(pid_t pid)
{
  return process_wait(pid);
}

bool sys_create(const char *file, unsigned initial_size)
{
  if (file == NULL) {
    sys_exit(-1); 
  }

  // if (!valid_access(file)) {
  //   sys_exit(-1); 
  // }
  valid_access(file);

  return filesys_create(file, initial_size); 
}

bool sys_remove(const char *file)
{
  valid_access(file);
  return filesys_remove(file);
}

int sys_open(const char *file)
{
  valid_access(file);

  struct file *f;
    
  lock_acquire(&file_lock);
  f = filesys_open(file);

  if (f == NULL) {
    lock_release(&file_lock);
    return -1;
  }

  if (!strcmp(thread_current()->name, file)) {
    file_deny_write(f);
  }

  int fd = thread_current()->fd_cnt;
  thread_current()->fd_table[fd] = f;
  thread_current() -> fd_cnt++;
  lock_release(&file_lock);
  return fd;
}

int sys_filesize(int fd)
{
  struct file *f;

  if(fd < thread_current()->fd_cnt) {
      f = thread_current()->fd_table[fd];
    return file_length(f);
   }
  else {
    f=NULL;
    return -1;
  }
}

int sys_read(int fd, void *buffer, unsigned size)
{
  for(int i=0;i<size;i++) {
    // if(!valid_access(buffer+i)) {
    //   sys_exit(-1);
    // }
    valid_access(buffer+i);
  }
  int read_size = 0;
  struct file *f;

  if (fd < 0) {
    sys_exit (-1);
  }

  if(thread_current()->fd_cnt < fd) {
    sys_exit (-1);
  }

  lock_acquire(&file_lock);

  if (fd == 0) { 
    unsigned int i;
    for (i = 0; i < size; i++) {
      if (((char *)buffer)[i] == '\0')
        break;
    }
    return i;
  }
  
  f = thread_current()->fd_table[fd];
  if (f == NULL) {
    sys_exit(-1);
  }
    
  read_size = file_read(f, buffer, size);

  lock_release(&file_lock);

  return read_size;
}

int sys_write(int fd, const void *buffer, unsigned size)
{
  for(int i=0;i<size;i++) {
    // if(!valid_access(buffer+i)) {
    //   sys_exit(-1);
    // }
    valid_access(buffer+i);
  }

  int write_size = 0;
  struct file *f;

  if (fd < 1) {
    sys_exit (-1);
  }

  if (fd > thread_current()->fd_cnt) {
    sys_exit(-1);
  }

  lock_acquire(&file_lock);

  if (fd == 1) { 
    putbuf(buffer, size);
    lock_release(&file_lock);
    return size;
  }
  else {
    f = thread_current()->fd_table[fd];

    if (f == NULL) {
      sys_exit(-1);
    }
    write_size = file_write(f, (const void *)buffer, size);
    lock_release(&file_lock);
    return write_size;
  }
}

void sys_seek(int fd, unsigned position)
{
  struct file *f;

  if(fd < thread_current()->fd_cnt) {
    f = thread_current()->fd_table[fd];
    file_seek(f, position);
  }
  else {
    f = NULL;
  }
  
}

unsigned sys_tell(int fd)
{
  struct file *f;

  if(fd < thread_current()->fd_cnt) {
    f = thread_current()->fd_table[fd];
    return file_tell(f);
   }
  else {
    f = NULL;
    return 0;
  }
}

void sys_close(int fd)
{
  struct file *f;
  if(fd < thread_current()->fd_cnt) {
      f = thread_current()->fd_table[fd];
   }
  else {
    f = NULL;
    return;
  }

  file_close(f);
  thread_current()->fd_table[fd] = NULL;
}

static void
syscall_handler(struct intr_frame *f)
{
  valid_access(f->esp);
  // if (!valid_access(f->esp)) {
  //   sys_exit(-1);
  // }
  
  void *args[3];
  switch (*(uint32_t *)(f->esp)) {
    case SYS_HALT:
      sys_halt();
      break;

    case SYS_EXIT:
      get_argument(f->esp + 4, args, 1);
      sys_exit((int)args[0]);
      break;

    case SYS_EXEC:
      get_argument(f->esp + 4, args, 1);

      f->eax = sys_exec((const char *)args[0]);
      break;

    case SYS_WAIT:
      get_argument(f->esp + 4, args, 1);
      f->eax = sys_wait((pid_t)args[0]);
      break;

    case SYS_CREATE:
      get_argument(f->esp + 4, args, 2);
      f->eax = sys_create((const char *)args[0], (unsigned)args[1]);
      break;

    case SYS_REMOVE:
      get_argument(f->esp + 4, args, 1);
      f->eax = sys_remove((const char *)args[0]);
      break;

    case SYS_OPEN:
      get_argument(f->esp + 4, args, 1);
      f->eax = sys_open((const char *)args[0]);
      break;

    case SYS_FILESIZE:
      get_argument(f->esp + 4, args, 1);
      f->eax = sys_filesize((int)args[0]);
      break;

    case SYS_READ:
      get_argument(f->esp + 4, args, 3);
      f->eax = sys_read((int)args[0], (void *)args[1], (unsigned)args[2]);
      break;

    case SYS_WRITE:
      get_argument(f->esp + 4, args, 3);
      f->eax = sys_write((int)args[0], (const void *)args[1], (unsigned)args[2]);
      break;

    case SYS_SEEK:
      get_argument(f->esp + 4, args, 2);
      sys_seek((int)args[0], (unsigned)args[1]);
      break;

    case SYS_TELL:
      get_argument(f->esp + 4, args, 1);
      f->eax = sys_tell((int)args[0]);
      break;

    case SYS_CLOSE:
      get_argument(f->esp + 4, args, 1);
      sys_close((int)args[0]);
      break;

    default:
      sys_exit(-1);
  }
}