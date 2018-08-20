#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include "libnet.h"

int blocking;

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
}

int arith_host_addr(unsigned char* p_buf)
{
	
	int cnt=0;

	while(strncmp(&p_buf[cnt], "Host: ", 6))
		cnt++;
	cnt+=6;
	return cnt;
	
}

int is_blocked(unsigned char* p_buf, int idx)
{	
	char* buf;
	FILE* fp = fopen("list.txt", "r");
	int size;
	int i=1;

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);

	buf = (char*)malloc(size + 1);
	memset(buf, 0, size + 1);

	fseek(fp, 0, SEEK_SET);
	fread(buf, size, 1, fp);

	while(memcmp((void*)&p_buf[idx+i], "\x0d", 1))
		i++;
	memcpy(&p_buf[idx+i], "\x00\x00", 4);

	printf("buf: %sp_buf: %s\n", buf, &p_buf[idx]);
	if(strstr(buf, &p_buf[idx+1]))
	{
		printf("blocked\n");
		return 1;
	}
	fclose(fp);
	free(buf);
	printf("hihi^^\n");
	return 0;
}
/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi; 
    int ret;
    unsigned char *data;
    struct libnet_ipv4_hdr* ip;
    struct libnet_tcp_hdr* tcp;
    unsigned char* http_data;
    int tcp_len;
    int idx;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    hwph = nfq_get_packet_hw(tb);
    mark = nfq_get_nfmark(tb);
    ifi = nfq_get_indev(tb);
    ifi = nfq_get_outdev(tb);
    ifi = nfq_get_physindev(tb);
    ifi = nfq_get_physoutdev(tb);
    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
	ip = (struct libnet_ipv4_hdr*)(data);
    	tcp = (struct libnet_tcp_hdr*)(data + sizeof(struct libnet_ipv4_hdr));
	if((ip->ip_p) == IPPROTO_TCP)
	{
		if(ntohs(tcp->th_dport) == 80)
		{
			tcp_len = tcp->th_off * 4;
			http_data = (unsigned char*)(data + sizeof(struct libnet_ipv4_hdr) + tcp_len);
			if(!strncmp(http_data, "GET", 3) || !strncmp(http_data, "POST", 4) || !strncmp(http_data, "HTTP", 4))
			{
			idx = arith_host_addr(http_data);
			blocking = is_blocked(http_data, idx);
			}
		}
	}

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);

	if(blocking ==1)
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	else
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

