#include <asm-generic/errno-base.h>
#include <asm/atomic.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0x434b");
MODULE_DESCRIPTION("Vulnerable training IOCTL kernel module for LIKE-DBG");
MODULE_VERSION("0.1");

/* Device name as populated in /dev/ */
#define DEV_NAME "vulnioctl"
#define BUF_SZ 0x400
#define EXIT_SUCCESS 0;

typedef struct {
  atomic_t available;
  struct semaphore sem;
  struct cdev cdev;
} likedbg_ioctl_d_iface;

char *gbuf;

likedbg_ioctl_d_iface ldbg_ioctl;

/* Private API */
int ioctl_open(struct inode *inode, struct file *filp);
int ioctl_release(struct inode *inode, struct file *filp);
long do_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
ssize_t ioctl_read(struct file *, char __user *, size_t, loff_t *);
ssize_t ioctl_write(struct file *, const char __user *, size_t, loff_t *);
static int ioctl_dev_init(likedbg_ioctl_d_iface *likedbg_ioctl);
static int ioctl_setup_cdev(likedbg_ioctl_d_iface *likedbg_ioctl);
static int ioctl_init(void);
static void ioctl_exit(void);

struct file_operations vuln_ioctl_fops = {.owner = THIS_MODULE,
                                          .read = NULL,
                                          .write = NULL,
                                          .open = ioctl_open,
                                          .unlocked_ioctl = do_ioctl,
                                          .release = ioctl_release};

static int ioctl_dev_init(likedbg_ioctl_d_iface *likedbg_ioctl) {
  int res = 0;
  memset(likedbg_ioctl, 0, sizeof(likedbg_ioctl_d_iface));
  atomic_set(&likedbg_ioctl->available, 1);
  sema_init(&likedbg_ioctl->sem, 1);
  return res;
}

static struct class *dev_class = NULL;
static dev_t dev_id;
struct cdev c_dev;
int dev_major = 0;
int dev_minor = 0;

static struct class *likedbgdev_class = NULL;

static int ioctl_setup_cdev(likedbg_ioctl_d_iface *likedbg_ioctl) {
  int err = 0;
  dev_major = MAJOR(dev_id);
  dev_minor = MINOR(dev_id);
  dev_id = MKDEV(dev_major, dev_minor);
  cdev_init(&likedbg_ioctl->cdev, &vuln_ioctl_fops);
  ldbg_ioctl.cdev.owner = THIS_MODULE;
  ldbg_ioctl.cdev.ops = &vuln_ioctl_fops;
  if (cdev_add(&ldbg_ioctl.cdev, dev_id, 1)) {
    pr_warn("FAILED TO ADD CDEV\n");
    err = -EBUSY;
  }
  return err;
}

static int likedbgdev_uevent(struct device *dev, struct kobj_uevent_env *env) {
  add_uevent_var(env, "DEVMODE=%#o", 0666);
  return EXIT_SUCCESS;
}

static int __init ioctl_init(void) {
  int res = 0;
  ioctl_dev_init(&ldbg_ioctl);
  if (alloc_chrdev_region(&dev_id, dev_minor, 1, DEV_NAME)) {
    res = -EBUSY;
    goto fail;
  }
  dev_class = class_create(THIS_MODULE, DEV_NAME);
  if (IS_ERR(dev_class)) {
    pr_warn("FAILED TO CREATE CLASS\n");
    res = -EBUSY;
    goto fail;
  }
  dev_class->dev_uevent = likedbgdev_uevent;

  res = ioctl_setup_cdev(&ldbg_ioctl);
  if (res < 0) {
    pr_warn("FAILED TO ADD LIKEDBG. ERR: %d\n", res);
    goto fail;
  }
  device_create(dev_class, NULL, MKDEV(dev_major, dev_minor), NULL, DEV_NAME);
  if (IS_ERR(dev_class)) {
    pr_warn("FAILED TO CREATE DEVICE\n");
    goto fail;
  }

  pr_info("IOCTL MODULE LOADED!\n");
  return EXIT_SUCCESS;

fail:
  ioctl_exit();
  return res;
}

// No __exit annotaion as our __init function references an error path to
// ioctl_exit
static void ioctl_exit(void) {
  device_destroy(dev_class, MKDEV(dev_major, dev_minor));
  class_destroy(dev_class);

  cdev_del(&ldbg_ioctl.cdev);
  unregister_chrdev_region(MKDEV(dev_major, dev_minor), MINORMASK);
  pr_info("GOODBYE\n");
}

/* Public API */
int ioctl_open(struct inode *inode, struct file *filp) {

  likedbg_ioctl_d_iface *ldbg_ioctl;
  ldbg_ioctl = container_of(inode->i_cdev, likedbg_ioctl_d_iface, cdev);
  filp->private_data = ldbg_ioctl;

  if (!atomic_dec_and_test(&ldbg_ioctl->available)) {
    atomic_inc(&ldbg_ioctl->available);
    pr_warn("IOCTL DEV HAS BEEN OPENED BY ANOTHER DEVICE. CANNOT LOCK IT\n");
    return -EBUSY;
  }
  pr_info("IOCTL GATE OPEN\n");
  return EXIT_SUCCESS;
}

int ioctl_release(struct inode *inode, struct file *filp) {
  likedbg_ioctl_d_iface *ldbg_ioctl = filp->private_data;
  atomic_inc(&ldbg_ioctl->available);
  pr_info("IOCTL GATE CLOSED\n");
  return EXIT_SUCCESS;
}

long do_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  unsigned int val;
  pr_warn("<%s> ioctl: %08x\n", DEV_NAME, cmd);
  switch (cmd) {
  case (0xdead0):
    val = 0x12345678;
    if (copy_to_user((uint32_t *)arg, &val, sizeof(val))) {
      return -EFAULT;
    }
    break;
  case (0xdead1):
    gbuf = kmalloc(BUF_SZ, GFP_KERNEL);
    break;
  case (0xdead2):
    if (gbuf) {
      kfree(gbuf);
    }
    break;
  case (0xdead3):
    if (_copy_to_user((char __user *)arg, gbuf, BUF_SZ)) {
      pr_warn("COPY_TO_USER FAILED\n");
      return -EFAULT;
    }
    break;
  case (0xdead4):
    if (_copy_from_user(gbuf, (char __user *)arg, BUF_SZ)) {
      pr_warn("COPY_from_USER FAILED\n");
      return -EFAULT;
    }
    break;
  default:
    break;
  }
  return EXIT_SUCCESS;
}

module_init(ioctl_init);
module_exit(ioctl_exit);
