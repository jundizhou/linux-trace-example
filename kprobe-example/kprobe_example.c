
#define pr_fmt(fmt) "%s: " fmt, __func__

#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

static struct kprobe kp = {
	.symbol_name	= "tcp_drop",
};

/* kprobe pre_handler: called just before the probed instruction is executed */
static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs)
{
#ifdef CONFIG_X86
        struct sock *sk = (struct sock*)regs->di;
#endif
        const struct inet_sock *inet = inet_sk(sk);
	u16 sport = 0;
	u16 dport = 0;
	sport = ntohs(inet->inet_sport);
	dport = ntohs(inet->inet_dport);
        printk("tcp drop happend , sport:%d , dport:%d \n",sport,dport);
	return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void __kprobes handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
}

static int __init kprobe_init(void)
{
	int ret;
	kp.pre_handler = handler_pre;
	kp.post_handler = handler_post;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}
	pr_info("Planted kprobe at %p\n", kp.addr);
	return 0;
}

static void __exit kprobe_exit(void)
{
	unregister_kprobe(&kp);
	pr_info("kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
