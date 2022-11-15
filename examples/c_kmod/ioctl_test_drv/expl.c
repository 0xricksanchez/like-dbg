#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define IOCTL_DRIVER_NAME "/dev/vulnioctl"

int open_driver(const char *driver_name);
void close_driver(const char *driver_name, int fd_driver);

int open_driver(const char *driver_name) {
  printf("[>] Opening %s from user-land!\n", driver_name);
  int fd_driver = open(driver_name, O_RDWR);
  if (fd_driver == -1) {
    printf("ERROR: could not open \"%s\".\n", driver_name);
    printf("    errno = %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  return fd_driver;
}

void close_driver(const char *driver_name, int fd_driver) {
  printf("[>] Closing %s from user-land!\n", driver_name);
  int result = close(fd_driver);
  if (result == -1) {
    printf("ERROR: could not close \"%s\".\n", driver_name);
    printf("    errno = %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
}

void do_ioctl(unsigned long cmd, int fd) {
  switch (cmd) {
  case (0xdead0): {
    uint32_t value = 0;
    if (ioctl(fd, cmd, &value) < 0) {
      perror("Error ioctl PL_AXI_DMA_GET_NUM_DEVICES");
      exit(EXIT_FAILURE);
    }
    printf("Value is %#08x\n", value);
    break;
  }
  case (0xdead1): {
    if (ioctl(fd, cmd, NULL) < 0) {
      perror("Error ioctl: 0xdead1\n");
      exit(EXIT_FAILURE);
    }
    break;
  }
  case (0xdead2): {
    if (ioctl(fd, cmd, NULL) < 0) {
      perror("Error ioctl: 0xdead2\n");
      exit(EXIT_FAILURE);
    }
    break;
  }
  case (0xdead3): {
    uint64_t sz = 0x400 / sizeof(uint64_t);
    uint64_t buf[sz];
    if (ioctl(fd, cmd, &buf) < 0) {
      perror("Error ioctl: 0xdead3\n");
      exit(EXIT_FAILURE);
    }
    for (uint64_t i = 0; i <= sz; i++) {
      uint64_t val = buf[i];
      if (val != 0) {
        printf("[IDX + %4lu] -> %#18lx\n", i * sizeof(uint64_t), val);
      }
    }
    break;
  }
  case (0xdead4): {
    char *ptr = "Hello World Yo!\n";
    if (ioctl(fd, cmd, ptr) < 0) {
      perror("Error ioctl: 0xdead4\n");
      exit(EXIT_FAILURE);
    }
  }
  default:
    break;
  }
}

int main(void) {

  int fd_ioctl = open_driver(IOCTL_DRIVER_NAME);
  do_ioctl(0xdead0, fd_ioctl);
  do_ioctl(0xdead1, fd_ioctl);
  do_ioctl(0xdead4, fd_ioctl);
  do_ioctl(0xdead3, fd_ioctl);
  do_ioctl(0xdead2, fd_ioctl);
  do_ioctl(0xdead3, fd_ioctl);

  close_driver(IOCTL_DRIVER_NAME, fd_ioctl);

  return EXIT_SUCCESS;
}
