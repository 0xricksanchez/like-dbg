#include <asm-generic/errno-base.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0x434b");
MODULE_DESCRIPTION("Dummy kernel module that highlights how to incorporate a "
                   "kernel module into LIKE-DBG");
MODULE_VERSION("0.1");

/* Prototyes section*/
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char __user *, size_t,
                            loff_t *);

/* Device name as populated in /dev/ */
#define DEV_NAME "likedbg"
/* Max amount of bytes to echo back to the user */
#define BUF_SZ 0x100
/* Default buffer contents */
#define BUF_CONTENT "Welcome to the LIKE-DBG echo service demo...\n"
#define EXIT_SUCCESS 0;

char *gbuf = NULL;

static int device_open(struct inode *inode, struct file *file) {
  pr_info("DEVICE_OPEN CALLED\n");
  gbuf = kmalloc(BUF_SZ, GFP_KERNEL);
  if (!gbuf) {
    pr_warn("KMALLOC FAILED\n");
    return -ENOMEM;
  }
  memcpy((void *)gbuf, (void *)BUF_CONTENT, sizeof(BUF_CONTENT));

  return EXIT_SUCCESS;
}

static ssize_t device_read(struct file *file, char __user *buf, size_t count,
                           loff_t *f_pos) {
  size_t len = count < (BUF_SZ - (*f_pos)) ? count : (BUF_SZ - (*f_pos));
  pr_info("DEVICE_READ CALLED\n\tREADING %lu bytes (Requested: %lu)\n", len,
          count);
  if (copy_to_user(buf, gbuf, len)) {
    pr_warn("COPY_TO_USER FAILED\n");
    return -EINVAL;
  }
  (*f_pos) += len;
  return len;
}

static ssize_t device_write(struct file *file, const char __user *buf,
                            size_t count, loff_t *f_pos) {
  size_t len = count < BUF_SZ ? count : BUF_SZ;
  pr_info("DEVICE_WRITE CALLED\n");
  if (copy_from_user(gbuf, buf, len)) {
    pr_warn("COPY_FROM_USER FAILED\n");
    return -EINVAL;
  }
  return len;
}

static int device_release(struct inode *inode, struct file *file) {
  pr_info("DEVICE_RELEASE CALLED\n");
  kfree(gbuf);
  return EXIT_SUCCESS;
}

struct file_operations echo_fops = {.owner = THIS_MODULE,
                                    .read = device_read,
                                    .write = device_write,
                                    .open = device_open,
                                    .release = device_release};

static int likedbgdev_uevent(struct device *dev, struct kobj_uevent_env *env) {
  add_uevent_var(env, "DEVMODE=%#o", 0666);
  return EXIT_SUCCESS;
}

static dev_t dev_id;
static struct cdev c_dev;
static int dev_major = 0;
static struct class *likedbgdev_class = NULL;

static int __init echo_init(void) {
  pr_info("HELLO");
  if (alloc_chrdev_region(&dev_id, 0, 1, DEV_NAME)) {
    pr_warn("FAILED TO REGISTER CHAR DEVICE: '%s'\n", DEV_NAME);
    return -EBUSY;
  }
  dev_major = MAJOR(dev_id);
  likedbgdev_class = class_create(THIS_MODULE, DEV_NAME);
  if (IS_ERR(likedbgdev_class)) {
    pr_warn("FAILED TO CREATE CLASS\n");
    return -EBUSY;
  }
  likedbgdev_class->dev_uevent = likedbgdev_uevent;

  cdev_init(&c_dev, &echo_fops);
  c_dev.owner = THIS_MODULE;

  if (cdev_add(&c_dev, MKDEV(dev_major, 0), 1)) {
    pr_warn("FAILED TO ADD CDEV\n");
    unregister_chrdev_region(MKDEV(dev_major, 0), MINORMASK);
    return -EBUSY;
  }
  device_create(likedbgdev_class, NULL, MKDEV(dev_major, 0), NULL, DEV_NAME);
  if (IS_ERR(likedbgdev_class)) {
    pr_warn("FAILED TO CREATE DEVICE\n");
    return -EBUSY;
  }
  return 0;
}

static void __exit echo_exit(void) {
  device_destroy(likedbgdev_class, MKDEV(dev_major, 0));
  class_destroy(likedbgdev_class);

  cdev_del(&c_dev);
  unregister_chrdev_region(MKDEV(dev_major, 0), MINORMASK);
  pr_info("GOODBYE\n");
}

module_init(echo_init);
module_exit(echo_exit);
