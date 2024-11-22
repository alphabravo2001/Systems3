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
static int memread_from_user (void *src, void *des, size_t bytes);

enum fd_search_filter { FD_FILE = 1, FD_DIRECTORY = 2 };

struct lock filesys_lock;

static struct file_desc* find_file_desc(struct thread *, int fd, enum fd_search_filter flag);


/** System Call Handler Function Declarations **/
void sys_halt(void);
void sys_exit(int status);
tid_t sys_exec(const char *cmd_line);
static int sys_wait(tid_t child_tid);
bool sys_create(const char* filename, unsigned initial_size);
bool sys_remove(const char* filename);
int sys_open(const char *file);
int sys_read(int fd, void *buffer, unsigned size);
int sys_filesize(int fd);
int sys_write(int fd, const void*buffer, unsigned size);
void sys_seek(int fd, unsigned pos);
unsigned sys_tell(int fd);
void sys_close(int fd);

void
syscall_init(void)
{
    lock_init (&filesys_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

//verify pointer is valid and mapped
bool is_valid_user_address_(const void *buffer, unsigned size) {
	for (unsigned i = 0; i < size; i++) {
		const void *addr = (const char *)buffer + i;
		if (addr == NULL || !is_user_vaddr(addr) || pagedir_get_page(thread_current()->pagedir, addr) == NULL) {
			return false;
		}
	}
	return true;
}

// in case of invalid memory access, fail and exit.
static void fail_invalid_access(void) {
    if (lock_held_by_current_thread(&filesys_lock))
        lock_release (&filesys_lock);

    sys_exit (-1);
    NOT_REACHED();
}

static void
check_user (const uint8_t *uaddr) {
    // check uaddr range or segfaults
    if(get_user (uaddr) == -1)
        fail_invalid_access();
}

static int32_t
get_user (const uint8_t *uaddr) {
    // check that a user pointer `uaddr` points below PHYS_BASE
    if (! ((void*)uaddr < PHYS_BASE)) {
        return -1;
    }

static int
memread_from_user(void *src, void *dst, size_t bytes)
{
    // Validate the entire memory range before proceeding
    if (!is_valid_user_address(src, bytes)) {
        sys_exit(-1); // Terminate the process for invalid memory access
    }

    // Copy memory from user space to destination
    size_t i;
    for (i = 0; i < bytes; i++) {
        *(char *)(dst + i) = *(char *)(src + i); // Safely copy byte by byte
    }

    return (int)bytes; // Return success
}

static bool
put_user (uint8_t *udst, uint8_t byte) {
    // check that a user pointer `udst` points below PHYS_BASE
    if (! ((void*)udst < PHYS_BASE)) {
        return false;
    }

    int error_code;

    // as suggested in the reference manual, see (3.1.5)
    asm ("movl $1f, %0; movb %b2, %1; 1:"
            : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}


static struct file_desc*
find_file_desc(struct thread *t, int fd, enum fd_search_filter flag)
{
  if (fd < 3) {
    return NULL;
  }

  struct list_elem *e;

  if (! list_empty(&t->file_descriptors)) {
    for(e = list_begin(&t->file_descriptors);
        e != list_end(&t->file_descriptors); e = list_next(e))
    {
      struct file_desc *desc = list_entry(e, struct file_desc, elem);
      if(desc->id == fd) {
        // found. filter by flag to distinguish file and directorys
        if (desc->dir != NULL && (flag & FD_DIRECTORY) )
          return desc;
        else if (desc->dir == NULL && (flag & FD_FILE) )
          return desc;
      }
    }
  }

  return NULL; // not found
}

static void
syscall_handler(struct intr_frame *f)
{
	uint32_t *esp = f->esp;

    memread_from_user(f->esp, &syscall_number, sizeof(syscall_number));

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
      	memread_from_user(f->esp + 4, &exitcode, sizeof(exitcode));

      	sys_exit(exitcode);
      	NOT_REACHED();
      	break;
	}

    case SYS_FILESIZE: // 7
    {
        int fd, ret;
        memread_from_user(f->esp + 4, &fd, sizeof(fd));

        ret = sys_filesize(fd);
        f->eax = ret;
        break;
    }

    case SYS_READ:
	{

		int fd, ret;
      	void *buffer;
      	unsigned size;

      	memread_from_user(f->esp + 4, &fd, sizeof(fd));
      	memread_from_user(f->esp + 8, &buffer, sizeof(buffer));
      	memread_from_user(f->esp + 12, &size, sizeof(size));

      	ret = sys_read(fd, buffer, size);
      	f->eax = (uint32_t) ret;
      	break;
	}

	case SYS_OPEN:
    {
      const char* filename;
      int ret;

      memread_from_user(f->esp + 4, &filename, sizeof(filename));

      ret = sys_open(filename);
      f->eax = ret;
      break;
    }

	case SYS_WRITE:
	{
        int fd;
        const void *buffer;
        unsigned size;

        /* Validate and extract arguments from user stack */
        memread_user(f->esp + 4, &fd, sizeof(fd));
        memread_user(f->esp + 8, &buffer, sizeof(buffer));
        memread_user(f->esp + 12, &size, sizeof(size));

        /* Pass the arguments to the sys_write implementation */
        f->eax = sys_write(fd, buffer, size);
	}

	case SYS_CREATE:
	{
	  const char* filename;
      unsigned initial_size;
      bool ret;

      memread_from_user(f->esp + 4, &filename, sizeof(filename));
      memread_from_user(f->esp + 8, &initial_size, sizeof(initial_size));

      ret = sys_create(filename, initial_size);
      f->eax = ret;
      break;
	}

	case SYS_REMOVE:
	{
		const char* filename;
		bool ret;

		memread_from_user(f->esp + 4, &filename, sizeof(filename));

		ret = sys_remove(filename);
		f->eax = ret;
		break;
	}

	case SYS_WAIT:
	 {
		tid_t child_tid = *(esp + 1);
		f->eax = sys_wait(child_tid);
		break;

	 }

     case SYS_SEEK: // 10
     {
         int fd;
         unsigned position;

         memread_from_user(f->esp + 4, &fd, sizeof(fd));
         memread_from_user(f->esp + 8, &position, sizeof(position));

         sys_seek(fd, position);
         break;
     }

     case SYS_TELL: // 11
     {
         int fd;
         unsigned ret;

         memread_from_user(f->esp + 4, &fd, sizeof(fd));

         ret = sys_tell(fd);
         f->eax = (uint32_t) ret;
         break;
     }

     case SYS_CLOSE: // 12
     {
         int fd;
         memread_from_user(f->esp + 4, &fd, sizeof(fd));

         sys_close(fd);
         break;
     }

	default:
		sys_exit(-1);
	}
}


/** System Call Handler Function Implementations **/

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

    int ret;
    lock_acquire(&filesys_lock);

    //stdout
    if (fd == 1)
    {
        putbuf(buffer, size);
        return size;
    }
    //writing to file
    else{
        struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);
        if(file_d && file_d->file) {
            ret = file_write(file_d->file, buffer, size);
        }
        else {
            ret = -1;     //inavalid file or no file desc
        }
    }

    lock_release(&filesys_lock);
    return ret;
}

bool sys_create(const char* filename, unsigned initial_size) {
    bool ret;

    lock_acquire(&filesys_lock);
    ret = filesys_create(filename, initial_size, false);
    lock_release(&filesys_lock);
    return ret;
}

bool sys_remove(const char* filename) {
    bool ret;

    lock_acquire(&filesys_lock);
    ret = filesys_remove(filename);
    lock_release(&filesys_lock);
    return ret;
}

int sys_open(const char *file_name) {

}
    lock_acquire(&filesys_lock);

    // Attempt to open the file
    struct file *file = filesys_open(file_name);
    if (file == NULL) {
        lock_release(&filesys_lock);
        return -1;   // File could not be opened
    }

    // Allocate memory for a file descriptor structure
    struct file_desc *fd_entry = malloc(sizeof(struct file_desc));
    if (fd_entry == NULL) {
        file_close(file);  // Clean up the opened file
        lock_release(&filesys_lock);
        sys_exit(-1);   // Memory allocation failed
    }

    // Initialize the file descriptor structure
    fd_entry->file = file;
    fd_entry->id = thread_current()->max_fd++;  // Assign the next available FD

    // Add the file descriptor to the current thread's list
    list_push_back(&thread_current()->file_descriptors, &fd_entry->elem);

    lock_release(&filesys_lock);
    return fd_entry->id;
}

int sys_read(int fd, void *buffer, unsigned size) {

    int ret;

    lock_acquire (&filesys_lock);

    // stdin
    if (fd == 0) {
        unsigned i;
        for (i = 0; i < size; ++i) {
            if (!put_user(buffer + i, input_getc())) {
                lock_release(&filesys_lock);
                sys_exit(-1);
            }
        }
        ret = size;
    }
    else{
        struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);

        if(file_d && file_d->file) {
            ret = file_read(file_d->file, buffer, size);
        }
        else{
            return -1;
        }
    }

    lock_release(&filesys_lock);
    return ret;
}


int sys_filesize(int fd) {
    struct file_desc* file_d;

    lock_acquire(&filesys_lock);
    file_d = find_file_desc(thread_current(), fd, FD_FILE);

    //check for invalid fd
    if (file_d == NULL) {
        lock_release (&filesys_lock);
        sys_exit(-1);
    }

    int ret = file_length(file_d->file);
    lock_release(&filesys_lock);

    return ret;
}


tid_t sys_exec(const char *cmd_line) {
    if (!is_user_vaddr(cmd_line)) {
        sys_exit(-1);
    }
    return process_execute(cmd_line);
}

void sys_seek(int fd, unsigned pos) {

    lock_acquire(&filesys_lock);
    struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);

    if(file_d && file_d->file) {
        file_seek(file_d->file, pos);
    }
    else {
        sys_exit(-1);
    }

    lock_release(&filesys_lock);
}

unsigned sys_tell(int fd){

    lock_release(&filesys_lock);
    struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);

    unsigned ret;
    if (file_d && file_d->file) {
        ret = file_tell(file_d->file);
    }
    else{
        sys_exit(-1);
    }
    lock_release(&filesys_lock);
}

void sys_close(int fd) {

    lock_acquire(&filesys_lock);
    struct file_desc *file_d = find_file_desc(thread_current(), fd, FD_FILE | FD_DIRECTORY);

    //check valid and non-null fd
    if (file_d && file_d->file) {
        file_close(file_d->file);

        // close dir if it is directory
        if (file_d->dir) {
            list_remove(&(file_d->elem));
        }
        list_remove(&(file_d->elem));
        free(file_d);
    }
    lock_release(&filesys_lock);
}
