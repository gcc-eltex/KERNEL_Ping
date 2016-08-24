#include "km_netping.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ivannikov Igor");

static unsigned int nf_hookpack(void *priv, struct sk_buff *skb,
		       const struct nf_hook_state *state)
{
	/* Input headers (request) */
	struct ethhdr	*eth;
	struct iphdr	*ip;
	struct icmphdr	*icmp;

	/* Output headers (reply) */
	struct sk_buff	*skbr;
	struct ethhdr	*ethr;
	struct iphdr	*ipr;
	struct icmphdr	*icmpr;

	unsigned int	len_skb;
	unsigned int	len_icmp;

	eth	= (struct ethhdr *)eth_hdr(skb);
	ip	= (struct iphdr *)ip_hdr(skb);
	icmp	= (struct icmphdr *)icmp_hdr(skb);

	/* Filtering traffic. Drop the only ICMP requests */
	if (ip->protocol != IPPROTO_ICMP || icmp->type != ICMP_ECHO)
		goto skip_packet;

	/* Prepares structure skb_reply */
	len_icmp = ntohs(ip->tot_len) - sizeof(struct iphdr);
	len_skb	= sizeof(struct ethhdr) + sizeof(struct iphdr) + len_icmp;
	skbr = alloc_skb(len_skb, /*GFP_KERNEL*/GFP_ATOMIC);
	if (!skbr)
		goto error_alloc;
	/*
	 * In this case, it is not necessary to keep room for the tail
	 * and the head.
	 */
	skb_reserve(skbr, len_skb);
	skb_push(skbr, len_skb);
	skbr->sk	= skb->sk;
	skbr->dev	= state->in;

	/* Prepares MAC header*/
	skb_set_mac_header(skbr, 0);
	ethr = (struct ethhdr *)eth_hdr(skbr);
	memmove(ethr, eth, sizeof(struct ethhdr));
	memmove(ethr->h_dest, eth->h_source, ETH_ALEN);
	memmove(ethr->h_source, eth->h_dest, ETH_ALEN);

	/* Prepares IP header */
	skb_set_network_header(skbr, sizeof(struct ethhdr));
	ipr = (struct iphdr *)ip_hdr(skbr);
	memmove(ipr, ip, sizeof(struct iphdr));
	ipr->saddr	= ip->daddr;
	ipr->daddr	= ip->saddr;
	ipr->ttl	= 64;
	ipr->check	= 0;
	ipr->tot_len	= htons(sizeof(struct iphdr) + len_icmp);
	ipr->check	= ip_compute_csum((void *)ipr, sizeof(struct iphdr));

	/* Prepares ICMP header */
	skb_set_transport_header(skbr, sizeof(struct ethhdr) +
				       sizeof(struct iphdr));
	icmpr = (struct icmphdr *)icmp_hdr(skbr);
	memmove(icmpr, icmp, len_icmp);
	icmpr->type	= ICMP_ECHOREPLY;
	icmpr->checksum = 0;
	icmpr->checksum = ip_compute_csum((void *)icmpr, len_icmp);
	dev_queue_xmit(skbr);
	pr_info("nf_hookpack: Send reply");
	/*
	 * Do not remove the structure skbr. This will be done automatically
	 * once the package sending.
	 * kfree_skb(skbr);
	 */
	return NF_DROP;

error_alloc:
	pr_info("nf_hookpack: A memory allocation error");
	return NF_ACCEPT;

skip_packet:
	return NF_ACCEPT;
}

static struct nf_hook_ops nfhops;

static int kmnet_init(void)
{
	memset(&nfhops, 0, sizeof(nfhops));
	nfhops.hook	= nf_hookpack;
	nfhops.pf	= PF_INET;
	nfhops.hooknum	= NF_INET_LOCAL_IN;
	nfhops.priority	= NF_IP_PRI_FIRST;
	nf_register_hook(&nfhops);

	pr_info("module_init: Module installed");
	return 0;
}

static void kmnet_exit(void)
{
	nf_unregister_hook(&nfhops);
	pr_info("module_exit: Module removed");
}

module_init(kmnet_init);
module_exit(kmnet_exit);