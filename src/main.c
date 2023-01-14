#include <utils.h>

void try_hop(tracert *p)
{
	while (p->hop_num < 31)
	{
		p->try_hop_num = -1;
		if (hop_tracert(p))
		{
			break;
		}
		p->hop_num++;
	}
}

int main(int c, char **v)
{
	tracert trace;
	init_tracert(&trace);

	trace.ip = dns_lookup(v[1], &trace.addr);
	if (trace.ip)
	{
		printf("traceroute to %s, ip: %s, 30 hops max,", v[1], trace.ip);
		printf(" %zu byte packets\n", (sizeof(struct ip) + sizeof(struct icmphdr)));

		try_hop(&trace);
		free(trace.buffer);
	}

	return 0;
}