// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * udeco_rl: per-station speed limits for the Garage AP (JioFiber JCOW414,
 * EcoNet EN7528, Linux 3.18.21, MIPS32el) run by the udeco agent.
 *
 * The unit's kernel has no traffic control (CONFIG_NET_SCHED is off), so
 * the controller's user-group limits are enforced here: a token-bucket
 * policer per station and direction, in bytes, on the bridge's FORWARD
 * hook (every frame the Linux bridge forwards between its ports).
 *
 *  - download: a frame leaving on a Wi-Fi port (the bridge port's name
 *    starts with wifi_prefix, "ra": ra0-3, rai0-3) whose destination MAC
 *    has an entry with a download limit;
 *  - upload: a frame arriving on a Wi-Fi port whose source MAC has an entry
 *    with an upload limit.
 *
 * Nothing else is ever touched: the unit's own traffic (not forwarded),
 * frames between wired ports, broadcast and multicast, and frames of
 * stations without an entry pass unchanged. A frame is dropped only when
 * its station's bucket is in debt; a bucket with a positive balance lets
 * any frame through (a 64 KB GRO frame too, then repaid at the rate), so a
 * limited station is slowed, never cut off. ARP and other non-IP frames,
 * DHCP/DHCPv6 and IPv6 neighbour discovery always pass (uncharged): a
 * saturated limit never costs a station its address or its neighbours.
 *
 * Hardware NAT (Jio's hw_nat.ko, the EN7528 PPE) can bind a bridged flow
 * and forward its later frames past the bridge, so past this hook. For
 * every frame of a limited station the FOE tag the PPE binds from
 * (sk_buff bytes 0xb4..0xba: hw_nat PpeTxHandler/ppe_check_start_to_bind
 * bind only a frame whose u16 magic at 0xb4 is a FOE magic; PpeXferHandler
 * zeroes the same 7 bytes) is cleared, so the PPE never binds its flows.
 * Flows bound before a limit was set are dropped from the PPE table by a
 * "flush" line (hw_nat's own PpeCleanTableHandler, looked up by name, only
 * when hw_nat is loaded and live).
 *
 * Interface: /proc/udeco_rl (0600).
 *   write: the whole table, one write: lines "<mac> <down_kbit> <up_kbit>"
 *          (0 = not limited that way), optional "flush" (hw_nat), "clear"
 *          or nothing for an empty table; '#' starts a comment. A bad line
 *          rejects the whole write (-EINVAL): the table is unchanged.
 *          Buckets of stations whose rate stays are kept.
 *   read:  "udeco_rl 1 entries=N hwnat=live|absent untag=0|1 ..." then one
 *          line per station: mac down up down_pass down_drop up_pass
 *          up_drop down_bytes up_bytes (packets, bytes passed).
 *
 * Unload (rmmod udeco_rl) removes the hook and the table: nothing remains.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/icmpv6.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ktime.h>
#include <linux/kallsyms.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>

#define RL_VERSION 1
#define RL_MAX 512           /* the agent's session caps the list at 512 */
#define RL_HASH 256
#define RL_NONE 0xffff
#define RL_MAX_KBIT 10000000 /* 10 Gbit/s */
#define RL_MAX_WRITE 65536
#define RL_MAX_BURST (8u << 20)
#define NS 1000000000u

/* EcoNet EN7528 3.18.21 sk_buff (measured from the running kernel: the
 * agent's driver build patches skbuff.h to it). Built against any other
 * layout the module refuses to compile. */
_Static_assert(sizeof(struct sk_buff) == 496, "EcoNet sizeof(sk_buff)");
_Static_assert(offsetof(struct sk_buff, protocol) == 164, "EcoNet sk_buff.protocol");
_Static_assert(offsetof(struct sk_buff, mac_header) == 170, "EcoNet sk_buff.mac_header");
_Static_assert(offsetof(struct sk_buff, len) == 96, "EcoNet sk_buff.len");
_Static_assert(offsetof(struct sk_buff, head) == 480, "EcoNet sk_buff.head");
_Static_assert(offsetof(struct sk_buff, data) == 484, "EcoNet sk_buff.data");
_Static_assert(offsetof(struct sk_buff, tail) == 472, "EcoNet sk_buff.tail");
/* struct module: name right after state and the list (3.18) */
_Static_assert(offsetof(struct module, name) == 12, "struct module.name");

static char *wifi_prefix = "ra";
module_param(wifi_prefix, charp, 0444);
MODULE_PARM_DESC(wifi_prefix, "bridge ports whose name starts with this are the Wi-Fi side (ra: ra0-3, rai0-3)");
static unsigned int burst_ms = 250;
module_param(burst_ms, uint, 0644);
MODULE_PARM_DESC(burst_ms, "bucket depth in ms of the rate (1..1000)");
static unsigned int min_burst = 32768;
module_param(min_burst, uint, 0644);
MODULE_PARM_DESC(min_burst, "smallest bucket depth in bytes");
static unsigned int min_kbit = 64;
module_param(min_kbit, uint, 0444);
MODULE_PARM_DESC(min_kbit, "a lower limit is raised to this (the controller's dl_min/ul_min)");
static bool untag = true;
module_param(untag, bool, 0644);
MODULE_PARM_DESC(untag, "clear the hw_nat FOE tag of limited stations' frames (their flows are never bound)");
static bool hwnat_flush = true;
module_param(hwnat_flush, bool, 0644);
MODULE_PARM_DESC(hwnat_flush, "act on a \"flush\" line (hw_nat PpeCleanTableHandler)");
static unsigned int foe_off = 0xb4;
module_param(foe_off, uint, 0444);
MODULE_PARM_DESC(foe_off, "offset of the 7-byte hw_nat FOE tag in sk_buff (EcoNet: 0xb4)");
#define FOE_LEN 7

struct rl_dir {
	u32 rate;  /* bytes/s; 0 = not limited */
	u32 kbit;
	s64 tokens; /* nano-bytes (bytes * 1e9); in debt below 0 */
	s64 cap;
	s64 last;  /* ns */
	u64 pass, drop, bytes;
};

struct rl_entry {
	u8 mac[ETH_ALEN];
	u16 next;
	spinlock_t lock;
	struct rl_dir down, up;
};

struct rl_table {
	u32 n;
	u16 head[RL_HASH];
	struct rl_entry e[0];
};

static struct rl_table __rcu *rl_table;
static DEFINE_MUTEX(rl_mutex); /* writers, readers of /proc */
static atomic_t rl_exempt = ATOMIC_INIT(0);
static atomic_t rl_untagged = ATOMIC_INIT(0);
static unsigned int rl_flushes, rl_flush_fail;
static size_t prefix_len;

static inline unsigned int rl_hash(const u8 *m)
{
	return (m[3] ^ m[4] ^ (m[5] << 1) ^ (m[5] >> 7)) & (RL_HASH - 1);
}

static struct rl_entry *rl_find(struct rl_table *t, const u8 *mac)
{
	u16 i;

	for (i = t->head[rl_hash(mac)]; i != RL_NONE; i = t->e[i].next)
		if (ether_addr_equal(t->e[i].mac, mac))
			return &t->e[i];
	return NULL;
}

static inline bool rl_wifi(const struct net_device *dev)
{
	return dev && prefix_len && !strncmp(dev->name, wifi_prefix, prefix_len);
}

/* rl_exempt_frame: frames that are never dropped (nor charged): anything
 * that is not IPv4/IPv6, DHCP, DHCPv6, IPv6 neighbour discovery. skb->data
 * is the network header at the bridge's FORWARD hook. */
static bool rl_exempt_frame(struct sk_buff *skb)
{
	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr _iph, *iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
		struct udphdr _uh, *uh;

		if (!iph || iph->protocol != IPPROTO_UDP || (iph->frag_off & htons(0x1fff) /* IP_OFFSET */))
			return !iph;
		uh = skb_header_pointer(skb, iph->ihl * 4, sizeof(_uh), &_uh);
		return uh && (uh->dest == htons(67) || uh->dest == htons(68));
	}
	if (skb->protocol == htons(ETH_P_IPV6)) {
		struct ipv6hdr _h, *h = skb_header_pointer(skb, 0, sizeof(_h), &_h);
		u8 _t, *t;
		struct udphdr _uh, *uh;

		if (!h)
			return true;
		if (h->nexthdr == IPPROTO_UDP) {
			uh = skb_header_pointer(skb, sizeof(*h), sizeof(_uh), &_uh);
			return uh && (uh->dest == htons(546) || uh->dest == htons(547));
		}
		if (h->nexthdr != IPPROTO_ICMPV6)
			return false;
		t = skb_header_pointer(skb, sizeof(*h), 1, &_t);
		return t && *t >= 133 && *t <= 137; /* router solicitation .. redirect */
	}
	return true;
}

/* rl_conform charges len bytes to d (entry lock held): true = pass. A
 * bucket with a positive balance passes any frame (it may go into debt);
 * one in debt drops until refilled. */
static bool rl_conform(struct rl_dir *d, u32 len, s64 now)
{
	s64 dt = now - d->last;

	if (dt > 0) {
		if (dt > NS)
			dt = NS;
		d->tokens += (s64)((u64)(u32)dt * d->rate);
		if (d->tokens > d->cap)
			d->tokens = d->cap;
	}
	d->last = now;
	if (d->tokens <= 0) {
		d->drop++;
		return false;
	}
	d->tokens -= (s64)((u64)len * NS);
	d->pass++;
	d->bytes += len;
	return true;
}

static unsigned int rl_hook(const struct nf_hook_ops *ops, struct sk_buff *skb,
			    const struct net_device *in, const struct net_device *out,
			    int (*okfn)(struct sk_buff *))
{
	struct rl_table *t = rcu_dereference(rl_table);
	struct rl_entry *up = NULL, *down = NULL;
	const struct ethhdr *eth;
	bool ok = true;
	s64 now;
	u32 len;

	if (!t || !skb_mac_header_was_set(skb))
		return NF_ACCEPT;
	eth = eth_hdr(skb);
	if (rl_wifi(in) && !is_multicast_ether_addr(eth->h_source)) {
		up = rl_find(t, eth->h_source);
		if (up && !up->up.rate)
			up = NULL;
	}
	if (rl_wifi(out) && !is_multicast_ether_addr(eth->h_dest)) {
		down = rl_find(t, eth->h_dest);
		if (down && !down->down.rate)
			down = NULL;
	}
	if (!up && !down)
		return NF_ACCEPT;
	if (untag && foe_off + FOE_LEN <= offsetof(struct sk_buff, tail) && foe_off >= 172) {
		memset((u8 *)skb + foe_off, 0, FOE_LEN);
		atomic_inc(&rl_untagged);
	}
	if (rl_exempt_frame(skb)) {
		atomic_inc(&rl_exempt);
		return NF_ACCEPT;
	}
	len = skb->len + ETH_HLEN;
	now = ktime_to_ns(ktime_get());
	if (up) {
		spin_lock_bh(&up->lock);
		ok = rl_conform(&up->up, len, now);
		spin_unlock_bh(&up->lock);
	}
	if (ok && down) {
		spin_lock_bh(&down->lock);
		ok = rl_conform(&down->down, len, now);
		spin_unlock_bh(&down->lock);
	}
	return ok ? NF_ACCEPT : NF_DROP;
}

static struct nf_hook_ops rl_ops __read_mostly = {
	.hook = rl_hook,
	.owner = THIS_MODULE,
	.pf = NFPROTO_BRIDGE,
	.hooknum = NF_BR_FORWARD,
	/* after ebtables' filter FORWARD (guest isolation drops first) */
	.priority = NF_BR_PRI_FILTER_BRIDGED + 1,
};

/* ------------------------------------------------------------ hw_nat */

/* rl_hwnat returns hw_nat's PpeCleanTableHandler when hw_nat is loaded
 * and live (module_mutex held: no module unload can start meanwhile). */
static int (*rl_hwnat(void))(void)
{
	unsigned long a = kallsyms_lookup_name("PpeCleanTableHandler");
	struct module *m;

	if (!a)
		return NULL;
	m = __module_text_address(a);
	if (!m || strcmp(m->name, "hw_nat") || m->state != MODULE_STATE_LIVE)
		return NULL;
	return (int (*)(void))a;
}

static const char *rl_hwnat_state(void)
{
	const char *s;

	mutex_lock(&module_mutex);
	s = rl_hwnat() ? "live" : "absent";
	mutex_unlock(&module_mutex);
	return s;
}

static void rl_hwnat_flush(void)
{
	int (*fn)(void);

	mutex_lock(&module_mutex);
	fn = rl_hwnat();
	if (fn) {
		fn();
		rl_flushes++;
	} else {
		rl_flush_fail++;
	}
	mutex_unlock(&module_mutex);
}

/* ------------------------------------------------------------- table */

static s64 rl_cap(u32 rate)
{
	/* rate * ms / 1000 in 32 bits (rate <= 1.25e9): no 64-bit division */
	u32 ms = burst_ms < 1 ? 1 : burst_ms > 1000 ? 1000 : burst_ms;
	u32 bytes = rate / 1000 * ms + rate % 1000 * ms / 1000;

	if (bytes > RL_MAX_BURST)
		bytes = RL_MAX_BURST;

	if (bytes < min_burst)
		bytes = min_burst > RL_MAX_BURST ? RL_MAX_BURST : min_burst;
	return (s64)((u64)bytes * NS);
}

static void rl_dir_init(struct rl_dir *d, u32 kbit, const struct rl_dir *old, s64 now)
{
	if (kbit && kbit < min_kbit)
		kbit = min_kbit;
	d->kbit = kbit;
	d->rate = kbit * 125u;
	d->cap = d->rate ? rl_cap(d->rate) : 0;
	d->tokens = d->cap;
	d->last = now;
	if (old) {
		d->pass = old->pass;
		d->drop = old->drop;
		d->bytes = old->bytes;
		if (old->kbit == d->kbit && old->cap == d->cap) {
			d->tokens = old->tokens;
			d->last = old->last;
		}
	}
}

/* rl_parse fills t (room for RL_MAX entries) from buf; -EINVAL on any bad
 * line. */
static int rl_parse(char *buf, struct rl_table *t, bool *flush)
{
	char *line, *p = buf;
	unsigned int i;

	t->n = 0;
	for (i = 0; i < RL_HASH; i++)
		t->head[i] = RL_NONE;
	while ((line = strsep(&p, "\n")) != NULL) {
		char macs[18];
		unsigned int down, up, h;
		u8 mac[ETH_ALEN];
		char *c = strchr(line, '#');

		if (c)
			*c = 0;
		line = strim(line);
		if (!*line || !strcmp(line, "clear"))
			continue;
		if (!strcmp(line, "flush")) {
			*flush = true;
			continue;
		}
		if (sscanf(line, "%17s %u %u", macs, &down, &up) != 3 || !mac_pton(macs, mac) ||
		    is_multicast_ether_addr(mac) || is_zero_ether_addr(mac) ||
		    down > RL_MAX_KBIT || up > RL_MAX_KBIT)
			return -EINVAL;
		if (t->n >= RL_MAX)
			return -E2BIG;
		if (rl_find(t, mac))
			return -EINVAL;
		h = rl_hash(mac);
		memcpy(t->e[t->n].mac, mac, ETH_ALEN);
		t->e[t->n].down.kbit = down;
		t->e[t->n].up.kbit = up;
		t->e[t->n].next = t->head[h];
		t->head[h] = t->n;
		t->n++;
	}
	return 0;
}

static ssize_t rl_write(struct file *f, const char __user *ubuf, size_t count, loff_t *pos)
{
	struct rl_table *t, *old;
	bool flush = false;
	char *buf;
	unsigned int i;
	s64 now;
	int err;

	if (count > RL_MAX_WRITE)
		return -E2BIG;
	buf = vmalloc(count + 1);
	t = vzalloc(sizeof(*t) + RL_MAX * sizeof(struct rl_entry));
	if (!buf || !t) {
		vfree(buf);
		vfree(t);
		return -ENOMEM;
	}
	if (copy_from_user(buf, ubuf, count)) {
		err = -EFAULT;
		goto out;
	}
	buf[count] = 0;
	err = rl_parse(buf, t, &flush);
	if (err)
		goto out;
	mutex_lock(&rl_mutex);
	old = rcu_dereference_protected(rl_table, lockdep_is_held(&rl_mutex));
	now = ktime_to_ns(ktime_get());
	for (i = 0; i < t->n; i++) {
		struct rl_entry *e = &t->e[i], *o = old ? rl_find(old, e->mac) : NULL;

		spin_lock_init(&e->lock);
		if (o)
			spin_lock_bh(&o->lock);
		rl_dir_init(&e->down, e->down.kbit, o ? &o->down : NULL, now);
		rl_dir_init(&e->up, e->up.kbit, o ? &o->up : NULL, now);
		if (o)
			spin_unlock_bh(&o->lock);
	}
	rcu_assign_pointer(rl_table, t->n ? t : NULL);
	if (!t->n)
		vfree(t);
	t = NULL;
	synchronize_rcu(); /* no hook still reads the old table */
	vfree(old);
	mutex_unlock(&rl_mutex);
	if (flush && hwnat_flush)
		rl_hwnat_flush();
	err = count;
out:
	vfree(buf);
	vfree(t);
	return err;
}

static int rl_show(struct seq_file *s, void *v)
{
	struct rl_table *t;
	unsigned int i;

	mutex_lock(&rl_mutex);
	t = rcu_dereference_protected(rl_table, lockdep_is_held(&rl_mutex));
	seq_printf(s, "udeco_rl %d entries=%u hwnat=%s untag=%d flush=%d burst_ms=%u min_burst=%u min_kbit=%u prefix=%s exempt=%d untagged=%d flushes=%u flush_failed=%u\n",
		   RL_VERSION, t ? t->n : 0, rl_hwnat_state(), untag, hwnat_flush, burst_ms, min_burst,
		   min_kbit, wifi_prefix, atomic_read(&rl_exempt), atomic_read(&rl_untagged),
		   rl_flushes, rl_flush_fail);
	for (i = 0; t && i < t->n; i++) {
		struct rl_entry *e = &t->e[i];
		struct rl_dir d, u;

		spin_lock_bh(&e->lock);
		d = e->down;
		u = e->up;
		spin_unlock_bh(&e->lock);
		seq_printf(s, "%pM %u %u %llu %llu %llu %llu %llu %llu\n", e->mac, d.kbit, u.kbit,
			   d.pass, d.drop, u.pass, u.drop, d.bytes, u.bytes);
	}
	mutex_unlock(&rl_mutex);
	return 0;
}

static int rl_open(struct inode *inode, struct file *f)
{
	return single_open(f, rl_show, NULL);
}

static const struct file_operations rl_fops = {
	.owner = THIS_MODULE,
	.open = rl_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = rl_write,
};

static int __init rl_init(void)
{
	int err;

	prefix_len = wifi_prefix ? strlen(wifi_prefix) : 0;
	if (!prefix_len || prefix_len >= IFNAMSIZ)
		return -EINVAL;
	if (!proc_create("udeco_rl", 0600, NULL, &rl_fops))
		return -ENOMEM;
	err = nf_register_hook(&rl_ops);
	if (err) {
		remove_proc_entry("udeco_rl", NULL);
		return err;
	}
	pr_info("udeco_rl %d: per-station limits on bridge FORWARD, Wi-Fi ports %s*\n", RL_VERSION, wifi_prefix);
	return 0;
}

static void __exit rl_exit(void)
{
	struct rl_table *t;

	nf_unregister_hook(&rl_ops); /* synchronize_net: no hook runs after */
	remove_proc_entry("udeco_rl", NULL);
	mutex_lock(&rl_mutex);
	t = rcu_dereference_protected(rl_table, lockdep_is_held(&rl_mutex));
	RCU_INIT_POINTER(rl_table, NULL);
	mutex_unlock(&rl_mutex);
	vfree(t);
	pr_info("udeco_rl: unloaded\n");
}

module_init(rl_init);
module_exit(rl_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("udeco");
MODULE_DESCRIPTION("udeco per-station speed limits (bridge FORWARD policer)");
