#include "dhcpv6relay.h"

#include <pppd/pppd.h>
#include <pppd/options.h>

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

char pppd_version[] = PPPD_VERSION;

static
int dhcpv6relay_setserver(const char* cmd, const char** argv, int doit);
static bool dhcpv6relay_trusted = false;

static struct option options[] = {
    { "dhcpv6-server", o_wild, (void*) &dhcpv6relay_setserver,
	"DHCPv6 server to proxy DHCPv6 requests to" },
    { "dhcpv6-trusted", o_bool, &dhcpv6relay_trusted,
	"DHCPv6 trusted interface (allow incoming relay messages)",
	OPT_PRIO | 1 },
    { "dhcpv6-untrusted", o_bool, &dhcpv6relay_trusted,
	"DHCPv6 untrusted interface (discard incoming relay messages)",
	OPT_PRIOSUB },
    { NULL }
};

static char* dhcpv6relay_server = NULL;
static int dhcpv6relay_sock_ll = -1;
static int dhcpv6relay_sock_mc = -1;
static int dhcpv6relay_upstream = -1;
struct sockaddr_storage dhcpv6relay_sa;

static
const char* dhcpv6_type2string(int msg_type)
{
    switch (msg_type) {
    case DHCPv6_MSGTYPE_SOLICIT:
	return "solicit";
    case DHCPv6_MSGTYPE_ADVERTISE:
	return "advertise";
    case DHCPv6_MSGTYPE_REQUEST:
	return "request";
    case DHCPv6_MSGTYPE_CONFIRM:
	return "confirm";
    case DHCPv6_MSGTYPE_RENEW:
	return "renew";
    case DHCPv6_MSGTYPE_REBIND:
	return "rebind";
    case DHCPv6_MSGTYPE_REPLY:
	return "reply";
    case DHCPv6_MSGTYPE_RELEASE:
	return "release";
    case DHCPv6_MSGTYPE_DECLINE:
	return "decline";
    case DHCPv6_MSGTYPE_RECONFIGURE:
	return "reconfigure";
    case DHCPv6_MSGTYPE_INFORMATION_REQUEST:
	return "information_request";
    case DHCPv6_MSGTYPE_RELAY_FORW:
	return "relay-forw";
    case DHCPv6_MSGTYPE_RELAY_REPL:
	return "relay-repl";
    default:
	return NULL;
    }
}

static
int dhcpv6relay_setserver(const char* cmd, const char** argv, int doit)
{
    int r;
    struct addrinfo *ai = NULL, *i, hint = {
	.ai_flags = 0,
	.ai_family = 0, /* we *prefer* IPv6, but will accept IPv4 */
	.ai_socktype = SOCK_DGRAM, /* UDP */
	.ai_protocol = 0,
	.ai_addrlen = 0,
	.ai_addr = NULL,
	.ai_canonname = NULL,
	.ai_next = NULL,
    };
    char bfr_ip[INET6_ADDRSTRLEN];
    char bfr_port[6];

    if (doit == 0)
	return 1;

    free(dhcpv6relay_server);
    dhcpv6relay_server = NULL;

    if (!*argv || !**argv)
	return 1;

    r = getaddrinfo(*argv, "dhcpv6-server", &hint, &ai);
    if (r != 0) {
	error("DHCPv6 relay: Unable to set server address to %s: %s",
		*argv, gai_strerror(r));
	return 0;
    }

    dhcpv6relay_sa.ss_family = 0;
    for (i = ai; i && dhcpv6relay_sa.ss_family != AF_INET6; i = i->ai_next) {
	if (!dhcpv6relay_sa.ss_family || i->ai_family == AF_INET6) {
	    memcpy(&dhcpv6relay_sa, i->ai_addr, i->ai_addrlen);
	    if (dhcpv6relay_sa.ss_family == AF_INET6)
		break;
	}
    }

    freeaddrinfo(ai);
    if (dhcpv6relay_sa.ss_family) {
	getnameinfo((struct sockaddr*)&dhcpv6relay_sa, sizeof(dhcpv6relay_sa),
		bfr_ip, sizeof(bfr_ip),
		bfr_port, sizeof(bfr_port),
		NI_NUMERICHOST | NI_NUMERICSERV | NI_DGRAM);
	notice("DHCPv6 relay: Using server [%s]:%s", bfr_ip, bfr_port);

	dhcpv6relay_server = strdup(*argv);
    } else {
	error("DHCPv6 relay: Failed to resolve %s to an actual IP address.",
		*argv);
    }

    return 1;
}

static
void dhcpv6relay_down(void*, int)
{
    if (dhcpv6relay_sock_ll >= 0) {
	remove_fd(dhcpv6relay_sock_ll);
	close(dhcpv6relay_sock_ll);
	dhcpv6relay_sock_ll = -1;
    }
    if (dhcpv6relay_sock_mc >= 0) {
	remove_fd(dhcpv6relay_sock_mc);
	close(dhcpv6relay_sock_mc);
	dhcpv6relay_sock_mc = -1;
    }
}

static
int dhcpv6relay_init_upstream()
{
    /* use family from sa so that we can do DHCPv6 / IPv4. */
    dhcpv6relay_upstream = socket(dhcpv6relay_sa.ss_family, SOCK_DGRAM, 0);
    if (dhcpv6relay_upstream < 0) {
	error("DHCPv6 relay: Failed to bind upstream socket: %s",
		strerror(errno));
	return 0;
    }
    if (connect(dhcpv6relay_upstream, (struct sockaddr*)&dhcpv6relay_sa, sizeof(dhcpv6relay_sa)) < 0) {
	error("DHCPv6 relay: Failed to connect upstream socket: %s",
		strerror(errno));
	close(dhcpv6relay_upstream);
	dhcpv6relay_upstream = -1;
	return 0;
    }

    return 1;
}

static
void dhcpv6relay_client_event(int fd, void*)
{
    unsigned char buffer[1024];
    unsigned char fwd_head[256];
    const char* remote_id;
    const char* subscriber_id;
    struct iovec v[] = {
	{
	    .iov_base = fwd_head,
	    .iov_len = 0,
	},
	{
	    .iov_base = buffer,
	    .iov_len = 0,
	},
    };
    struct msghdr wv = {
	.msg_name = &dhcpv6relay_sa,
	.msg_namelen = sizeof(dhcpv6relay_sa),
	.msg_iov = v,
	.msg_iovlen = sizeof(v) / sizeof(*v),
	.msg_control = NULL,
	.msg_controllen = 0,
	.msg_flags = 0,
    };
    char in6addr[INET6_ADDRSTRLEN];
    struct sockaddr_in6 sa;
    uint16_t sport;
    socklen_t slen = sizeof(sa);
    ssize_t r = recvfrom(fd, buffer, sizeof(buffer), MSG_DONTWAIT,
	    (struct sockaddr*)&sa, &slen);
    if (r < 0) {
	error("DHCPv6 relay: Failed to read from %s socket: %s",
		fd == dhcpv6relay_sock_ll ? "LL" : "MC",
		strerror(errno));
	return;
    }
    if (r >= sizeof(buffer)) {
	error("DHCPv6 buffer overrun, recvfrom returned %d, max %u",
		r, sizeof(buffer));
	return;
    }
    v[1].iov_len = r;

    error("Reveived %d bytes from fd=%d (%s), with source [%s]:%d, packet type: %s", r, fd,
	    fd == dhcpv6relay_sock_ll ? "LL" : "MC",
	    inet_ntop(sa.sin6_family, &sa.sin6_addr, in6addr, sizeof(in6addr)),
	    ntohs(sa.sin6_port), dhcpv6_type2string(buffer[0]));

    /* disallow Reply and Relay-Reply messages */
    if (buffer[0] == DHCPv6_MSGTYPE_REPLY || buffer[0] == DHCPv6_MSGTYPE_RELAY_REPL) {
	warn("Discarding DHCPv6 %s message received on PPP interface.",
		dhcpv6_type2string(buffer[0]));
	return;
    }

    /* if the interface is not trusted, also discard Relay-Fwd messages */
    if (!dhcpv6relay_trusted && buffer[0] == DHCPv6_MSGTYPE_RELAY_FORW) {
	warn("Discarding DHCPv6 %s message received on untrusted PPP interface.",
		dhcpv6_type2string(buffer[0]));
	return;
    }

    if (dhcpv6relay_upstream < 0 && !dhcpv6relay_init_upstream())
	return;

    /* populate the forward header */
    fwd_head[0] = DHCPv6_MSGTYPE_RELAY_FORW; /* msg-type */
    fwd_head[1] = buffer[0] == DHCPv6_MSGTYPE_RELAY_FORW ? buffer[1] + 1 : 0; /* hop count */
    memset(&fwd_head[2], 0, 16); /* link-address, unspecified */
    memcpy(&fwd_head[18], &sa.sin6_addr, 16); /* peer-address */
    v[0].iov_len = 34;

    slen = sizeof(sa);
    if (getsockname(dhcpv6relay_upstream, (struct sockaddr*)&sa, &slen) < 0) {
	error("DHCPv6 relay: Unable to determine local sending port: %s",
		strerror(errno));
	return;
    }

#define push_checkbytes(x) do { if ((x) + v[0].iov_len > sizeof(fwd_head)) { error("DHCPv6 relay: Buffer overlow avoidance pushing %d bytes, need %d.", (x), (x) + v[0].iov_len - sizeof(fwd_head)); return; }} while(0)
#define push_uint16(val) do { push_checkbytes(2); uint16_t t = (val); fwd_head[v[0].iov_len++] = t >> 8; fwd_head[v[0].iov_len++] = t & 0xFF; } while(0);
#define push_bytes(ptr, bytes) do { push_checkbytes(bytes); memcpy(&fwd_head[v[0].iov_len], (ptr), (bytes)); v[0].iov_len += (bytes); } while(0)

    /* On Linux at least sin6_port and sin_port would refer the same
     * data but I can't guarantee that for solaris (and others) */
    switch (sa.sin6_family) {
    case AF_INET:
	sport = ((struct sockaddr_in*)&sa)->sin_port;
	break;
    case AF_INET6:
	sport = sa.sin6_port;
	break;
    default:
	error("DHCPv6 relay: Upstream socket is bound to something other than IP ... can't relay.");
	return;
    }

    push_uint16(DHCPv6_OPTION_RELAY_PORT);
    push_uint16(2);
    push_uint16(ntohs(sport));

    remote_id = ppp_get_remote_number();
    if (remote_id) {
	r = strlen(remote_id);
	push_uint16(DHCPv6_OPTION_REMOTE_ID);
	push_uint16(r);
	push_bytes(remote_id, r);
    }

    subscriber_id = ppp_peer_authname(NULL, 0);
    if (subscriber_id) {
	r = strlen(subscriber_id);
	push_uint16(DHCPv6_OPTION_SUBSCRIBER_ID);
	push_uint16(r);
	push_bytes(subscriber_id, r);
    }

    /* This *must* be the last option since it refers the the content from v[1] */
    push_uint16(DHCPv6_OPTION_RELAY_MSG);
    push_uint16(v[1].iov_len);

#undef push_checkbytes
#undef push_uint16
#undef push_bytes

    if (sendmsg(dhcpv6relay_upstream, &wv, 0) < 0) {
	error("DHCPv6 relay: Failed to transmit proxies request: %s",
		strerror(errno));
    }
}

static
void dhcpv6relay_server_event(int fd, void*)
{
	/* read response from the client socket */
	/* unwrap response */
	/* dispatch to the client over LL socket */
	/* Add/remove routes to the kernel as needed - this step can potentially
	 * create loops if the remote side doesn't install unreachable routes, so
	 * need to read spec. */
    fatal("Need to implement reading from the dhcp_server-facing sockets here.");
}

static
int dhcpv6relay_populate_ll(struct sockaddr_in6* res)
{
    /* can we rather shortcut to get the address directly from ipv6cp? */
    struct ifaddrs *ifap, *ifa;
    int r = getifaddrs(&ifap);
    const struct sockaddr_in6* sa6;

    if (r < 0) {
	error("DHCPv6 relay: Unable to determine LL address");
	return 0;
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET6)
	    continue;

	sa6 = (struct sockaddr_in6*)ifa->ifa_addr;
	if (!sa6->sin6_scope_id)
	    continue; /* LL has sin6_scope_id set to interface id, != 0 */

	if (strcmp(ifa->ifa_name, ppp_ifname()) != 0)
	    continue; /* wrong interface */

	/* use it */
	*res = *sa6;
	freeifaddrs(ifap);
	return 1;
    }

    error("DHCPv6 relay: No matching LL addresses available for use.");
    freeifaddrs(ifap);
    return 0;
}

static
void dhcpv6relay_up(void*, int)
{
    struct sockaddr_in6 sa;
    struct ipv6_mreq mreq;
    int hlim = 1;
    struct servent *se;

    /* no relay configured, so we can't work, simply don't listen
     * for DHCP solicitations */
    if (!dhcpv6relay_server)
	return;

    if (!dhcpv6relay_populate_ll(&sa))
	return;

    se = getservbyname("dhcpv6-server", "udp");
    if (!se) {
	error("DHCPv6 relay: Unable to determine UDP port number for dhcpv6-server: %s",
		strerror(errno));
	return;
    }

    sa.sin6_port = se->s_port;

    dhcpv6relay_sock_ll = socket(AF_INET6, SOCK_DGRAM, 0);
    if (dhcpv6relay_sock_ll < 0) {
	error("DHCPv6 relay: Unable to create LL socket: %s", strerror(errno));
	return dhcpv6relay_down(NULL, 0);
    }
    fcntl(dhcpv6relay_sock_ll, F_SETFD, FD_CLOEXEC);

    if (bind(dhcpv6relay_sock_ll, (const struct sockaddr*)&sa, sizeof(sa)) < 0) {
	error("DHCPv6 relay: Unable to bind LL socket: %s", strerror(errno));
	return dhcpv6relay_down(NULL, 0);
    }

    setsockopt(dhcpv6relay_sock_ll, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hlim, sizeof(hlim));

    memset(&mreq, 0, sizeof(mreq));
    if (inet_pton(AF_INET6, "ff02::1:2", &mreq.ipv6mr_multiaddr) < 0) {
	error("DHCPv6 relay: Error preparing multicast binding: %s", strerror(errno));
	return dhcpv6relay_down(NULL, 0);
    }

    mreq.ipv6mr_interface = sa.sin6_scope_id;
    if (setsockopt(dhcpv6relay_sock_ll, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0) {
	error("DHCPv6 relay: Error joining multicast group: %s", strerror(errno));
	return dhcpv6relay_down(NULL, 0);
    }

    dhcpv6relay_sock_mc = socket(AF_INET6, SOCK_DGRAM, 0);
    if (dhcpv6relay_sock_mc < 0) {
	error("DHCPv6 relay: Unable to create MC socket: %s", strerror(errno));
	return dhcpv6relay_down(NULL, 0);
    }
    fcntl(dhcpv6relay_sock_mc, F_SETFD, FD_CLOEXEC);

    sa.sin6_addr = mreq.ipv6mr_multiaddr;
    if (bind(dhcpv6relay_sock_mc, (const struct sockaddr*)&sa, sizeof(sa)) < 0) {
	error("DHCPv6 relay: Unable to bind MC socket: %s", strerror(errno));
	return dhcpv6relay_down(NULL, 0);
    }

    add_fd_callback(dhcpv6relay_sock_ll, dhcpv6relay_client_event, NULL);
    add_fd_callback(dhcpv6relay_sock_mc, dhcpv6relay_client_event, NULL);

    notice("DHCPv6 relay: ready.");
}

void
plugin_init(void)
{
    ppp_add_options(options);
    ppp_add_notify(NF_IPV6_UP, dhcpv6relay_up, NULL);
    ppp_add_notify(NF_IPV6_DOWN, dhcpv6relay_down, NULL);
}
