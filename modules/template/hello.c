// like-dbg out-of-tree module template: the minimal skeleton for a custom_modules entry. Copy this
// file (and the Makefile) into a new modules/<name>/ directory, rename obj-m += hello.o to your
// module's object name, and fill in real behavior. See modules/README.md.

#include <linux/module.h>
#include <linux/kernel.h>

static int __init hello_init(void)
{
	pr_info("likedbg: hello loaded\n");
	return 0;
}

static void __exit hello_exit(void)
{
	pr_info("likedbg: hello unloaded\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("like-dbg out-of-tree module template");
