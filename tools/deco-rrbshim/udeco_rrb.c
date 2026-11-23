// SPDX-License-Identifier: GPL-2.0-or-later
//
// udeco_rrb.so: LD_PRELOAD shim for the Deco X20's stock hostapd 2.9.
//
// The Deco's bridge (TP-Link's tpbr) drops every unicast frame of
// EtherType 0x88b7 before it reaches br-lan, so hostapd's 802.11r key
// holder messages (RRB-OUI: PMK-R1 pull, response, push, sequence
// request/response) from the other APs never arrive. The agent adds an
// ebtables broute rule for each FT BSSID that hands those frames to the
// stack on the port they came in on; this shim makes hostapd's 0x88b7
// sockets see them there:
//
//   bind()   an AF_PACKET socket of protocol 0x88b7 to an interface is
//            bound to all interfaces instead (the interface is kept);
//   send()   on such a socket goes out that interface (sendto with it).
//
// hostapd still drops a frame not addressed to one of its BSSes. Nothing
// else is changed.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ETH_P_OUI 0x88b7
#define MAXFD 1024

static int ifidx[MAXFD]; // fd -> interface it asked for; 0: not one of ours

int bind(int fd, const struct sockaddr *a, socklen_t l)
{
	if (fd >= 0 && fd < MAXFD)
		ifidx[fd] = 0;
	if (a && l >= sizeof(struct sockaddr_ll) && a->sa_family == AF_PACKET && fd >= 0 && fd < MAXFD) {
		const struct sockaddr_ll *ll = (const struct sockaddr_ll *)a;
		if (ll->sll_protocol == htons(ETH_P_OUI) && ll->sll_ifindex > 0) {
			struct sockaddr_ll any = *ll;
			any.sll_ifindex = 0;
			long r = syscall(SYS_bind, fd, (const struct sockaddr *)&any, sizeof(any));
			if (r == 0)
				ifidx[fd] = ll->sll_ifindex;
			return (int)r;
		}
	}
	return (int)syscall(SYS_bind, fd, a, l);
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
	if (fd >= 0 && fd < MAXFD && ifidx[fd] > 0) {
		struct sockaddr_ll ll;
		memset(&ll, 0, sizeof(ll));
		ll.sll_family = AF_PACKET;
		ll.sll_protocol = htons(ETH_P_OUI);
		ll.sll_ifindex = ifidx[fd];
		return (ssize_t)syscall(SYS_sendto, fd, buf, len, flags, (const struct sockaddr *)&ll, sizeof(ll));
	}
	return (ssize_t)syscall(SYS_sendto, fd, buf, len, flags, NULL, 0);
}

int close(int fd)
{
	if (fd >= 0 && fd < MAXFD)
		ifidx[fd] = 0;
	return (int)syscall(SYS_close, fd);
}
