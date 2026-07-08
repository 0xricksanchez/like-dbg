/*
 * lk01 - a deliberately vulnerable /dev/lk01 misc char device for like-dbg's kernel-exploitation
 * research sandbox (a Pawnyable/LK01-style training driver). Original, minimal, self-contained.
 *
 * lk01 is a tiny slot-based object manager: LK01_ALLOC kmalloc()s an object into a slot, LK01_WRITE
 * and LK01_READ copy to/from it, and LK01_FREE releases it.
 *
 * THE BUG (intentional): LK01_FREE kfree()s the object but never clears the slot, so the slot's
 * pointer is left dangling. LK01_WRITE and LK01_READ do guard the slot, but only by checking that
 * the pointer is non-NULL, which a freed-but-not-cleared slot still is. So a WRITE or READ after a
 * FREE is a USE-AFTER-FREE that the check does not catch. Nothing faults at the free; the symptom
 * shows up later on the dangling access (KASAN flags it immediately; a plain kernel corrupts freed
 * memory silently). Reclaim the freed slab with a controlled allocation and the dangling slot
 * becomes an arbitrary read/write primitive (see expl.c). Do not load this on anything but a
 * disposable debug kernel.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/minmax.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/types.h>

#define LK01_MAX_SLOTS 16
#define LK01_MAX_LEN 4096

struct lk01_req {
	__u32 idx;		/* slot index, 0 .. LK01_MAX_SLOTS-1 */
	__u32 len;		/* byte count for ALLOC/WRITE/READ */
	void __user *buf;	/* user buffer for WRITE/READ */
};

#define LK01_ALLOC _IOW('L', 1, struct lk01_req)
#define LK01_FREE _IOW('L', 2, struct lk01_req)
#define LK01_WRITE _IOW('L', 3, struct lk01_req)
#define LK01_READ _IOR('L', 4, struct lk01_req)

struct lk01_obj {
	void *ptr;
	size_t len;
};

static struct lk01_obj lk01_slots[LK01_MAX_SLOTS];
static DEFINE_MUTEX(lk01_lock);

/* noinline keeps these handlers as distinct symbols (so gdb `break lk01_write` works and KASAN
 * reports name the specific handler) instead of being inlined into lk01_ioctl. */
static noinline long lk01_alloc(const struct lk01_req *r)
{
	void *obj;

	if (r->idx >= LK01_MAX_SLOTS || r->len == 0 || r->len > LK01_MAX_LEN)
		return -EINVAL;
	if (lk01_slots[r->idx].ptr)
		return -EBUSY;
	obj = kmalloc(r->len, GFP_KERNEL);
	if (!obj)
		return -ENOMEM;
	lk01_slots[r->idx].ptr = obj;
	lk01_slots[r->idx].len = r->len;
	return 0;
}

static noinline long lk01_free(const struct lk01_req *r)
{
	if (r->idx >= LK01_MAX_SLOTS)
		return -EINVAL;
	/* VULN: releases the object but leaves lk01_slots[idx].ptr dangling (never cleared).
	 * A later WRITE/READ on this slot is a use-after-free. */
	kfree(lk01_slots[r->idx].ptr);
	return 0;
}

static noinline long lk01_write(const struct lk01_req *r)
{
	struct lk01_obj *o;

	if (r->idx >= LK01_MAX_SLOTS)
		return -EINVAL;
	o = &lk01_slots[r->idx];
	if (!o->ptr)	/* fig-leaf check: non-NULL is not the same as still-allocated */
		return -EINVAL;
	if (copy_from_user(o->ptr, r->buf, min_t(size_t, r->len, o->len)))
		return -EFAULT;
	return 0;
}

static noinline long lk01_read(const struct lk01_req *r)
{
	struct lk01_obj *o;

	if (r->idx >= LK01_MAX_SLOTS)
		return -EINVAL;
	o = &lk01_slots[r->idx];
	if (!o->ptr)	/* fig-leaf check: non-NULL is not the same as still-allocated */
		return -EINVAL;
	if (copy_to_user(r->buf, o->ptr, min_t(size_t, r->len, o->len)))
		return -EFAULT;
	return 0;
}

static long lk01_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct lk01_req r;
	long ret;

	if (copy_from_user(&r, (void __user *)arg, sizeof(r)))
		return -EFAULT;

	mutex_lock(&lk01_lock);
	switch (cmd) {
	case LK01_ALLOC:
		ret = lk01_alloc(&r);
		break;
	case LK01_FREE:
		ret = lk01_free(&r);
		break;
	case LK01_WRITE:
		ret = lk01_write(&r);
		break;
	case LK01_READ:
		ret = lk01_read(&r);
		break;
	default:
		ret = -ENOTTY;
	}
	mutex_unlock(&lk01_lock);
	return ret;
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
	/* Training driver on a disposable kernel: any still-allocated slots leak on unload. We do
	 * NOT free them here, because a slot freed via the buggy LK01_FREE is dangling and freeing
	 * it again would be a double free on rmmod. */
	misc_deregister(&lk01_dev);
	pr_info("lk01: unloaded\n");
}

module_init(lk01_init);
module_exit(lk01_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("like-dbg");
MODULE_DESCRIPTION("Deliberately vulnerable LK01 training driver (use-after-free object manager)");
