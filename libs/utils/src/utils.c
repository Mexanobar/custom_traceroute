#include <utils.h>

char *dns_lookup(const char *addr_host, struct sockaddr_in *addr_con)
{
	char *ip = (char *)malloc(INET_ADDRSTRLEN);

	struct addrinfo hints;
	memset(&(hints), 0, sizeof(hints));
	hints.ai_family = AF_INET;

	struct addrinfo *res;
	if (getaddrinfo(addr_host, NULL, &hints, &(res)) < 0)
	{
		printf("unknown host\n");
		return NULL;
	}

	struct sockaddr_in *sa_in;
	sa_in = (struct sockaddr_in *)res->ai_addr;
	// из структуры с сетевым адресом создаётся строка символов
	inet_ntop(res->ai_family, &(sa_in->sin_addr), ip, INET_ADDRSTRLEN);

	*addr_con = *sa_in;
	(*addr_con).sin_port = htons(PORT_NO);
	return ip;
}

unsigned short checksum(const char *const buffer, int len)
{
    unsigned short *buf = (unsigned short *)buffer;
    unsigned int sum = 0;

	while (len > 0)
	{
		sum += *buf++;
		len--;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

    return ~sum; // "~" == "NOT"; т.к. из обратного кода
}


int init_tracert(tracert *trace)
{
	trace->hop_num = 1;
	trace->len = sizeof(struct sockaddr_in);
	trace->buffer = malloc(4096);
	trace->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	trace->tv_out.tv_sec = RECV_TIMEOUT;
	trace->tv_out.tv_usec = 0;

	int optval = 1;
	if (setsockopt(trace->sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int)) < 0)
    {
		printf("error setsockopt\n");
        return 0;
    }
	setsockopt(trace->sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&trace->tv_out, sizeof(trace->tv_out));

	return 1;
}

void *create_pkg_tracert(const int hop_num, char *ip, char *buff)
{
	struct ip *ip_hdr;
	ip_hdr = (struct ip *)buff;
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = sizeof(struct ip) + sizeof(struct icmphdr);
	ip_hdr->ip_id = 10000;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = hop_num; // Главное для traceroute
	ip_hdr->ip_p = IPPROTO_ICMP;
	inet_pton(AF_INET, ip, &(ip_hdr->ip_dst)); // Создание структуры с сетевым адресом
	ip_hdr->ip_sum = checksum(buff, 9);

	struct icmphdr *icmphd;
	icmphd = (struct icmphdr *)(buff + sizeof(struct ip));
	icmphd->type = ICMP_ECHO;
	icmphd->code = 0;
	icmphd->checksum = 0;
	icmphd->un.echo.id = 0;
	icmphd->un.echo.sequence = hop_num + 1;
	icmphd->checksum = checksum((buff + 20), 4);

	return buff;
}

void print_hop_tracert(tracert *p, const int try_hop_num)
{
	char *ipa = inet_ntoa(p->addr2.sin_addr); // IP-адрес в массив символов
	struct ip *ip = (struct ip *)p->buff;
	struct hostent *c = gethostbyaddr((void*)&(ip->ip_src.s_addr), sizeof(ip->ip_src.s_addr), AF_INET);

	printf("hop number: %2d, address: %s, ip: %s, total time: %.3f ms\n", p->hop_num, c ? c->h_name : ipa
		, ipa, p->total_time);
}

int hop_tracert(tracert *p)
{
	while (++(p->try_hop_num) < 3)
	{
		p->sbuff = create_pkg_tracert(p->hop_num, p->ip, p->buffer);
		gettimeofday(&p->start_time, NULL);
		sendto(p->sockfd, p->sbuff, sizeof(struct ip) + sizeof(struct icmphdr), 0, SA& p->addr, sizeof(p->addr));
		if (!(recvfrom(p->sockfd, p->buff, sizeof(p->buff), 0, SA& p->addr2, &p->len) <= 0))
		{
			gettimeofday(&p->end_time, NULL);
			p->total_time = ((p->end_time.tv_usec - p->start_time.tv_usec) / 1000.0);
			p->icmphd2 = (struct icmphdr *)(p->buff + sizeof(struct ip));			
			print_hop_tracert(p, p->try_hop_num);

			if (p->icmphd2->type == 0)
			{
				return 1;
			}
			break;
		}
		else
		{
			printf("Hop unsuccessful, trying again...\n");
		}
	}
	return 0;
}