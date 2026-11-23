# SPDX-License-Identifier: GPL-2.0-or-later
#
# econet_skb.py SKBUFF_H: rewrites struct sk_buff in a vanilla 3.18.21
# include/linux/skbuff.h, in place, to the layout of the EcoNet EN7528
# kernel on the JioFiber JCOW414 (offsets measured from the running kernel).
# A module built against the vanilla layout reads every field after nfct at
# the wrong offset. The _Static_asserts it appends fail the build if the
# layout ever drifts.
import sys

path = sys.argv[1]
src = open(path).read()
if "EcoNet EN7528 layout checks" in src:
    sys.exit("econet_skb: %s is already patched" % path)


def sub(old, new):
    global src
    assert src.count(old) == 1, old[:60]
    src = src.replace(old, new)


sub("""#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	struct nf_conntrack	*nfct;
#endif
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	struct nf_bridge_info	*nf_bridge;
#endif
	unsigned int		len,""", """	struct nf_conntrack	*nfct;		/* EcoNet: 84 */
	__u32			__econet_pad88;	/* EcoNet: 88, unknown vendor field */
	struct nf_bridge_info	*nf_bridge;	/* EcoNet: 92 */
	unsigned int		len,""")
sub("""	__u16			inner_mac_header;

	__be16			protocol;""", """	__u16			inner_mac_header;
	__u8			__econet_pad152[12];	/* EcoNet: 152..163 vendor fields */
	__be16			protocol;""")
sub("""	__u32			headers_end[0];
	/* public: */
""", """	__u32			headers_end[0];
	/* public: */
	__u8			__econet_pad172[300];	/* EcoNet: 172..471 vendor fields (hw_nat/QoS) */
""")

offsets = {"next": 0, "tstamp": 8, "sk": 16, "dev": 20, "cb": 24, "_skb_refdst": 72, "destructor": 76, "sp": 80,
           "nfct": 84, "nf_bridge": 92, "len": 96, "data_len": 100, "mac_len": 104, "hdr_len": 106,
           "queue_mapping": 108, "headers_start": 112, "csum": 116, "priority": 120, "hash": 128,
           "vlan_proto": 132, "vlan_tci": 134, "mark": 140, "protocol": 164, "transport_header": 166,
           "network_header": 168, "mac_header": 170, "headers_end": 172, "tail": 472, "end": 476,
           "head": 480, "data": 484, "truesize": 488, "users": 492}
chk = "\n/* EcoNet EN7528 layout checks */\n" + "".join(
    '_Static_assert(__builtin_offsetof(struct sk_buff, %s) == %d, "EcoNet sk_buff.%s");\n' % (k, v, k)
    for k, v in offsets.items())
chk += '_Static_assert(sizeof(struct sk_buff) == 496, "EcoNet sizeof(sk_buff)");\n'
i = src.find("\n};", src.find("\nstruct sk_buff {")) + 3
src = src[:i] + chk + src[i:]
open(path, "w").write(src)
print("econet_skb: patched %s" % path)
