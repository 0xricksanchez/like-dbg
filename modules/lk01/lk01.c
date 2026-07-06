/*
 * lk01 — deliberately vulnerable /dev/lk01 misc char device for like-dbg's kernel-exploitation
 * research sandbox (a Pawnyable/LK01-style training driver). Original, minimal, self-contained.
 *
 * THE BUG (intentional): LK01_COPY takes a user-supplied `struct lk01_arg { len, ptr }` and copies
 * `len` bytes from `ptr` into a FIXED 64-byte stack buffer with NO bounds check. Any `len > 64`
 * overflows `kbuf` on the kernel stack — a classic stack smash, the starting point for further
 * exploitation (see expl.c). Do not load this on anything but a disposable debug kernel.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/types.h>

struct lk01_arg {
	size_t len;
	void __user *ptr;
};

#define LK01_COPY _IOW('L', 1, struct lk01_arg)

static long lk01_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct lk01_arg karg;
	char kbuf[64]; /* fixed-size stack buffer — see the bug note above */

	switch (cmd) {
	case LK01_COPY:
		if (copy_from_user(&karg, (void __user *)arg, sizeof(karg)))
			return -EFAULT;
		/* VULN: no check that karg.len <= sizeof(kbuf). A large karg.len smashes the stack. */
		if (copy_from_user(kbuf, karg.ptr, karg.len))
			return -EFAULT;
		pr_info("lk01: copied %zu bytes into a %zu-byte stack buffer\n", karg.len, sizeof(kbuf));
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations lk01_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = lk01_ioctl,
};

static struct miscdevice lk01_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "lk01",
	.fops = &lk01_fops,
};

static int __init lk01_init(void)
{
	int ret = misc_register(&lk01_dev);

	if (ret) {
		pr_err("lk01: misc_register failed: %d\n", ret);
		return ret;
	}
	pr_info("lk01: loaded, /dev/lk01 ready\n");
	return 0;
}

static void __exit lk01_exit(void)
{
	misc_deregister(&lk01_dev);
	pr_info("lk01: unloaded\n");
}

module_init(lk01_init);
module_exit(lk01_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("like-dbg");
MODULE_DESCRIPTION("Deliberately vulnerable LK01 training driver (unchecked copy_from_user stack overflow)");
