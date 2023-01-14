#ifndef UTILS_H
#define UTILS_H

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>				// addrinfo etc
#include <sys/time.h>
#include <sys/socket.h>			// setsockopt
#include <netinet/ip_icmp.h>	// ip struct
#include <arpa/inet.h>			// formatting functions

#define SA (struct sockaddr*)
#define RECV_TIMEOUT 1
#define PORT_NO 1

typedef struct TRACERT
{
	char *buffer;
	char buff[4096];
	socklen_t len;
	struct sockaddr_in addr;
	struct sockaddr_in addr2;
	struct icmphdr *icmphd2;
	char *sbuff;
	char *ip;
	int hop_num;
	int try_hop_num;
	int sockfd;
	struct timeval tv_out;
	struct timeval start_time;
	struct timeval end_time;
	double total_time;
} tracert;

char *dns_lookup(const char *addr_host, struct sockaddr_in *addr_con);
unsigned short checksum(const char *const buffer, int len);

int init_tracert(tracert *trace);
void print_hop_tracert(tracert *p, const int n);
int hop_tracert(tracert *p);
void *create_pkg_tracert(const int hop, char *ip, char *buff);

#endif // UTILS_H