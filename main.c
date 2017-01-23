#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <regex.h>
#define tcpdata 40  // about
#define ipheader 20
int DROPURL=0;
regex_t regex;
/* tcp와 http패킷 사이에 다른 값이 존재함 12byte정도
와이어샤크도 queue를 공유함!!
 48 6f 73 74  Host
 0d 0a \r\n
tcp_data = 40; // ip header + tcp header  no eth
beacuse netfilter dont have eth header  */

void hexdump(unsigned char *buf,int size)
{
    int i;
    for(i=0;i<size;i++)
    {
            if(i%16==0)
            {
                printf("\n");
            }
        printf("%02x ",buf[i]);
    }
}

int chkurl(unsigned char *buf,int size) // using regex
{
    char chkbuf[size]; // protect buffer over flow
    int first=0,i=0;
    int reg; //reg result
    DROPURL=0;
    for(int k=0;k<size;k++)
    {
       chkbuf[first]=buf[i]; // input host url in chkbuf
       if(buf[i]==0x0d && buf[i+1]==0x0a)
       {
         chkbuf[first+2]='\0';
         break;
       }
       i++,first++;
    }
    if(!regexec(&regex, chkbuf, 0, NULL, 0)) // Execute regular expression
    {
         printf("\n**this is bad url");
         printf("\n**request is denied");
         DROPURL=1;
         return DROPURL;
    }
}
int chkhost(unsigned char *buf,int size) // input is buf[tcpdata],size-tcpdata
{
    if(!(buf[9]==0x06 && buf[ipheader+2]==0x00 && buf[ipheader+3]==0x50)) // only http protocol 80 port 23&&24 byte 0050
         return 0;
    for(int i=tcpdata;i<size;i++)
    {
        if(buf[i]==0x48 && buf[i+1]==0x6f && buf[i+2]==0x73 && buf[i+3]==0x74) //short circuit
         {
            // printf("\nfind host ");
            // printf("\n%c,%c,%c,%c",buf[i],buf[i+1],buf[i+2],buf[i+3]);
             return i;
         }

     }
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

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
      /* printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id); */
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
      // printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data); //ret는 패킷의 길이
    if (ret >= 0)
    {
       // printf("payload_len=%d ", ret);
        int hostloc; // hostloca 안에 +40 만큼 되어있음
        hostloc=chkhost(data,ret); // if detect host then return value is host location
        if(hostloc)
                chkurl(&data[hostloc],ret-(hostloc)); // if url is bad so DROPURL=1
    }

    fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data) //call back function
{
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");
    if(DROPURL)
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL); //NF_DROP을 하면 DROP을 한것과 같음

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
    char *badurl="naver.com";
    regcomp(&regex, badurl, 0); // Compile regular expression

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
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. Please, see
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
