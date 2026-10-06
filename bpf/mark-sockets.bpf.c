/*
 * Mark sockets created by processes in the agy and Codex cgroups.
 * Linux policy routing uses the mark to select the WireGuard route table.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define WG_APP_MARK 0x57474150
#define WG_SOL_SOCKET 1
#define WG_SO_MARK 36

static __always_inline int mark_socket(void *ctx)
{
	int mark = WG_APP_MARK;

	/* Reject connect/sendmsg if the socket could not be marked. */
	return bpf_setsockopt(ctx, WG_SOL_SOCKET, WG_SO_MARK, &mark, sizeof(mark)) == 0;
}

SEC("cgroup/connect4")
int route_connect4(struct bpf_sock_addr *ctx)
{
	return mark_socket(ctx);
}

SEC("cgroup/connect6")
int route_connect6(struct bpf_sock_addr *ctx)
{
	return mark_socket(ctx);
}

SEC("cgroup/sendmsg4")
int route_sendmsg4(struct bpf_sock_addr *ctx)
{
	return mark_socket(ctx);
}

SEC("cgroup/sendmsg6")
int route_sendmsg6(struct bpf_sock_addr *ctx)
{
	return mark_socket(ctx);
}

char wg_app_route_license[] SEC("license") = "GPL";
