#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/syscall.h"

#include "userprog/process.h"

static void syscall_handler(struct intr_frame *);
static int32_t get_user (const uint8_t *uaddr);
static int memread_user (void *src, void *des, size_t bytes);

void
syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static int32_t
get_user (const uint8_t *uaddr) {
  // check that a user pointer `uaddr` points below PHYS_BASE
  if (! ((void*)uaddr < PHYS_BASE)) {
    return -1;
  }

  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
  return result;
}

//verify pointer is valid and mapped
bool is_valid_user_address(const void *buffer, unsigned size) {
	for (unsigned i = 0; i < size; i++) {
		const void *addr = (const char *)buffer + i;
		if (addr == NULL || !is_user_vaddr(addr) || pagedir_get_page(thread_current()->pagedir, addr) == NULL) {
			return false;
		}
	}
	return true;
}

static int
memread_user (void *src, void *dst, size_t bytes)
{
  int32_t value;
  size_t i;
  for(i=0; i<bytes; i++) {
    value = get_user(src + i);
    // if(value == -1) // segfault or invalid memory access
    //   fail_invalid_access();

    *(char*)(dst + i) = value & 0xff;
  }
  return (int)bytes;
}

void sys_halt(void) {
	shutdown_power_off();
}

static int sys_wait(tid_t child_tid) {
	return process_wait(child_tid);
}

void sys_exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->name, status);

  struct process_control_block *pcb = thread_current()->pcb;
  if(pcb != NULL) {
    pcb->exitcode = status;
  }

  thread_exit();
}

int sys_write(int fd, const void*buffer, unsigned size)
{
	if (!is_valid_user_address(buffer, size)) {
		sys_exit(-1);  // Terminate process for bad memory access
	}

	if (fd == 1)
	{
		putbuf(buffer, size);
		return size;
	}
	return -1;
}

bool sys_create(const char* filename, unsigned initial_size) {
  bool return_code;
  return_code = filesys_create(filename, initial_size, false);
  return return_code;
}

bool sys_remove(const char* filename) {
	bool return_code;

	return_code = filesys_remove(filename);
	return return_code;
}

int sys_open(const char *file) {
	struct file* file_opened;
	struct file_desc* fd = palloc_get_page(0);
  if (!fd) {
    return -1;
  }

  file_opened = filesys_open(file);
  if (!file_opened) {
    palloc_free_page (fd);
    return -1;
  }

  fd->file = file_opened; //file save

  // directory handling
  struct inode *inode = file_get_inode(fd->file);
  fd->dir = NULL;

  struct list* fd_list = &thread_current()->file_descriptors;
  if (list_empty(fd_list)) {
    // 0, 1, 2 are reserved for stdin, stdout, stderr
    fd->id = 3;
  }
  else {
    fd->id = (list_entry(list_back(fd_list), struct file_desc, elem)->id) + 1;
  }
  list_push_back(fd_list, &(fd->elem));

  return fd->id;

}

int sys_read(int fd, void *buffer, unsigned size) {
  int ret = -1;
    struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);

    if(file_d && file_d->file) {
		ret = file_read(file_d->file, buffer, size);
	}


  return ret;
}


tid_t sys_exec(const char *cmd_line) {
	if (!is_user_vaddr(cmd_line)) {
		sys_exit(-1);
	}
	return process_execute(cmd_line);
}

//int sys_wait(tid_t tid) {
//	return process_wait(tid);
//}

static void
syscall_handler(struct intr_frame *f)
{
	uint32_t *esp = f->esp;

	switch (*esp)
	{

	case SYS_HALT: // 0
	{
		sys_halt();
		NOT_REACHED();
		break;
	}

	case SYS_EXIT:
	{
		int exitcode;
      	memread_user(f->esp + 4, &exitcode, sizeof(exitcode));

      	sys_exit(exitcode);
      	NOT_REACHED();
      	break;
	}

    case SYS_READ:
	{

		int fd, return_code;
      	void *buffer;
      	unsigned size;

      	memread_user(f->esp + 4, &fd, sizeof(fd));
      	memread_user(f->esp + 8, &buffer, sizeof(buffer));
      	memread_user(f->esp + 12, &size, sizeof(size));

      	return_code = sys_read(fd, buffer, size);
      	f->eax = (uint32_t) return_code;
      	break;
	}

	case SYS_OPEN:
    {
      const char* filename;
      int return_code;

      memread_user(f->esp + 4, &filename, sizeof(filename));

      return_code = sys_open(filename);
      f->eax = return_code;
      break;
    }

	case SYS_WRITE:
	{
		int fd = *(esp + 1);
		const void *buffer = (const void *)*(esp + 2);
		unsigned size = *(esp + 3);
		f->eax = sys_write(fd, buffer, size);
		break;

	}

	case SYS_CREATE:
	{
	  const char* filename;
      unsigned initial_size;
      bool return_code;

      memread_user(f->esp + 4, &filename, sizeof(filename));
      memread_user(f->esp + 8, &initial_size, sizeof(initial_size));

      return_code = sys_create(filename, initial_size);
      f->eax = return_code;
      break;
	}

	case SYS_REMOVE:
	{
		const char* filename;
		bool return_code;

		memread_user(f->esp + 4, &filename, sizeof(filename));

		return_code = sys_remove(filename);
		f->eax = return_code;
		break;
	}

	case SYS_WAIT:
	 {
		tid_t child_tid = *(esp + 1);
		f->eax = sys_wait(child_tid);
		break;


	 }
	default:
		sys_exit(-1);
	}
}
