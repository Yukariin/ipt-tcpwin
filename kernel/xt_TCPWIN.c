#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/checksum.h>

#include <linux/netfilter/x_tables.h>

#include "xt_TCPWIN.h"

MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_TCPWIN");

static unsigned int tcpwin_tg(struct sk_buff *skb,
			      const struct xt_action_param *par)
{
	const struct xt_TCPWIN_info *info = par->targinfo;
	struct iphdr *iph;
	struct tcphdr *tcph;
	int offset, len;

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;

	if (skb_linearize(skb))
		return NF_DROP;

	iph = ip_hdr(skb);
	tcph = tcp_hdr(skb);

	if (iph && iph->protocol) {
		tcph->window = htons(info->size);

		offset = skb_transport_offset(skb);
		len = skb->len - offset;
		tcph->check = 0;
		tcph->check = csum_tcpudp_magic(
			(iph->saddr), (iph->daddr), len, IPPROTO_TCP,
			csum_partial((char *)tcph, len, 0));
		skb->ip_summed = CHECKSUM_NONE;
	}

	return XT_CONTINUE;
}

static int tcpwin_check(const struct xt_tgchk_param *par)
{
	if (strcmp(par->table, "mangle")) {
		printk(KERN_WARNING
		       "TCPWIN: can only be called from"
		       "\"mangle\" table, not \"%s\"\n",
		       par->table);
		return -EINVAL;
	}

	return 0;
}

static struct xt_target tcpwin_tg_reg __read_mostly = {
	.name = "TCPWIN",
	.family = NFPROTO_IPV4,
	.proto = IPPROTO_TCP,
	.target = tcpwin_tg,
	.targetsize = sizeof(struct xt_TCPWIN_info),
	.checkentry = tcpwin_check,
	.table = "mangle",
	.me = THIS_MODULE,
};

static int __init tcpwin_tg_init(void)
{
	return xt_register_target(&tcpwin_tg_reg);
}

static void __exit tcpwin_tg_exit(void)
{
	xt_unregister_target(&tcpwin_tg_reg);
}

module_init(tcpwin_tg_init);
module_exit(tcpwin_tg_exit);
