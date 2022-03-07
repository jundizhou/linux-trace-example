
BPF_KPROBE(tcp_drop)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	settings = get_bpf_settings();
	if (!settings)
		return 0;

	struct sock *sk = (struct sock *)_READ(ctx->di);
	const struct inet_sock *inet = inet_sk(sk);
	u16 sport = 0;
	u16 dport = 0;
	bpf_probe_read(&sport, sizeof(sport), (void *)&inet->inet_sport);
	bpf_probe_read(&dport, sizeof(dport), (void *)&inet->inet_dport);
	sk = NULL;
	bpf_printk("%d", sk->__sk_common.skc_family);
	bpf_printk("tcp drop happend , sport:%d , dport:%d \n",sport,dport);
	return 0;
}

