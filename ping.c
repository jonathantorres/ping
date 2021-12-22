#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <unistd.h>

void sig_finish();
int in_cksum(u_short *ptr, int nbytes);
void pr_pack(char *buf, int cc, struct sockaddr_in *from);
char *pr_type(int t);
void tvsub(struct timeval *out, struct timeval *in);
void recv_ping();
void send_ping();
void sig_alarm();

extern int errno;

// should be in <netinet/in.h>
#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

// max time to wait for response, sec.
#define MAXWAIT 10

/*
 * Beware that the outgoing packet starts with the ICMP header and
 * does not include the IP header (the kernel prepends that for us).
 * But, the received packet includes the IP header.
 */
#define MAXPACKET 4096

// should be defined in <param.h>
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#define SIZE_ICMP_HDR  8  // 8-byte ICMP header
#define SIZE_TIME_DATA 8  // then the BSD timeval struct (ICMP "data")
#define DEF_DATALEN    56 // default data area after ICMP header

// size of ICMP packets to send
// this includes the 8-byte ICMP header
int packsize;

// size of data after the ICMP header, it may be 0
// if >= SIZE_TIME_DATA, timing is done
int datalen;

// enables additional error messages
int verbose;

// the packet we send
u_char sendpack[MAXPACKET];

// the received packet
char recvpack[MAXPACKET];

// destination to ping
struct sockaddr_in dest;

// socket file descriptor
int sockfd;

char *hostname;
int npackets;     // max # of packets to send; 0 if no limit
int ident;        // our process ID, to identify ICMP packets
int ntransmitted; // sequence # for outbound packets = #sent
int nreceived;    // # of packets we got back

int timing;  // true if time-stamp in each packet */
int tmin;    // min round-trip time */
int tmax;    // max round-trip time */

// sum of all round-trip times, for average
// above 3 times are in milliseconds
long tsum;

char *usage = "Usage: ping [ -drv ] host [ datasize ] [ npackets ]\n";
char hnamebuf[MAXHOSTNAMELEN];
char *pname;

int main(int argc, char **argv)
{
    int sockoptions, on;
    char *destdotaddr;
    struct hostent  *host;
    struct protoent *proto;

    on = 1;
    pname = argv[0];
    argc--;
    argv++;
    sockoptions = 0;

    while (argc > 0 && *argv[0] == '-') {
        while (*++argv[0]) switch (*argv[0]) {
            case 'd':
                sockoptions |= SO_DEBUG;
                break;
            case 'r':
                sockoptions |= SO_DONTROUTE;
                break;
            case 'v':
                verbose++;
                break;
        }
        argc--, argv++;
    }

    if (argc < 1) {
        puts(usage);
        exit(1);
    }

    /*
     * Assume the host is specified by numbers (Internet dotted-decimal)
     * and call inet_addr() to convert it. If that doesn't work, then
     * assume its a name and call gethostbyname() to look it up.
     */
    bzero((char *) &dest, sizeof(dest));
    dest.sin_family = AF_INET;

    if ((dest.sin_addr.s_addr = inet_addr(argv[0])) != INADDR_NONE) {
        strcpy(hnamebuf, argv[0]);
        hostname = hnamebuf;
        destdotaddr = NULL;
    } else {
        if ((host = gethostbyname(argv[0])) == NULL) {
            printf("host name error: %s\n", argv[0]);
        }
        dest.sin_family = host->h_addrtype;
        bcopy(host->h_addr, (caddr_t) &dest.sin_addr, host->h_length);
        hostname = host->h_name;

        // convert to dotted-decimal notation
        destdotaddr = inet_ntoa(dest.sin_addr);
    }

    /*
     * If the user specifies a size, that is the size of the data area
     * following the ICMP header that is transmitted. If the data area
     * is large enough for a "struct timeval", then enable timing.
     */
    if (argc >= 2) {
        datalen = atoi(argv[1]);
    } else {
        datalen = DEF_DATALEN;
    }

    packsize = datalen + SIZE_ICMP_HDR;
    if (packsize > MAXPACKET) {
        puts("packet size too large");
        exit(1);
    }
    if (datalen >= SIZE_TIME_DATA) {
        timing = 1;
    }

    // The user can specify the maximum number of packets to receive.
    if (argc > 2) {
        npackets = atoi(argv[2]);
    }

    /*
     * Fetch our Unix process ID.  We use that as the "ident" field
     * in the ICMP header, to identify this process' packets.
     * This allows multiple copies of ping to be running on a host
     * at the same time.  This identifier is needed to separate
     * the received ICMP packets (since all readers of an ICMP
     * socket get all the received packets).
     */
    ident = getpid() & 0xffff;

    // Create the socket.
    if ((proto = getprotobyname("icmp")) == NULL) {
        puts("unknown protocol: icmp");
        exit(1);
    }
    if ((sockfd = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0) {
        perror("can't create raw socket");
        exit(1);
    }
    if (sockoptions & SO_DEBUG) {
        if (setsockopt(sockfd, SOL_SOCKET, SO_DEBUG, &on, sizeof(on)) < 0) {
            perror("setsockopt SO_DEBUG error");
            exit(1);
        }
    }
    if (sockoptions & SO_DONTROUTE) {
        if (setsockopt(sockfd, SOL_SOCKET, SO_DONTROUTE, &on, sizeof(on)) < 0) {
            perror("setsockopt SO_DONTROUTE error");
            exit(1);
        }
    }

    printf("PING %s", hostname);
    if (destdotaddr) {
        printf(" (%s)", destdotaddr);
    }
    printf(": %d data bytes\n", datalen);
    tmin = 99999999;

    setlinebuf(stdout);         // one line at a time
    signal(SIGINT, sig_finish); // to let user stop program
    signal(SIGALRM, sig_alarm); // invoked every second
    sig_alarm();                // start the output going
    recv_ping();                // and start the receive

    return 0;
}

// return checksum in low-order 16 bits
int in_cksum(u_short *ptr, int nbytes)
{
    // assumes long == 32 bits
    long sum;

    // assumes u_short == 16 bits
    u_short answer;
    u_short oddbyte;

    /*
     * Our algorithm is simple, using a 32-bit accumulator (sum),
     * we add sequential 16-bit words to it, and at the end, fold back
     * all the carry bits from the top 16 bits into the lower 16 bits.
     */
    sum = 0;
    while (nbytes > 1)  {
        sum += *ptr++;
        nbytes -= 2;
    }

    // mop up an odd byte, if necessary
    if (nbytes == 1) {
        oddbyte = 0; // make sure top half is zero
        *((u_char *) &oddbyte) = *(u_char *)ptr; // one byte only
        sum += oddbyte;
    }

    // Add back carry outs from top 16 bits to low 16 bits.
    sum  = (sum >> 16) + (sum & 0xffff); // add high-16 to low-16
    sum += (sum >> 16); // add carry
    answer = ~sum; // ones-complement, then truncate to 16 bits

    return answer;
}

void sig_finish()
{
    printf("\n----%s PING Statistics----\n", hostname);
    printf("%d packets transmitted, ", ntransmitted);
    printf("%d packets received, ", nreceived);
    if (ntransmitted) {
        printf("%d%% packet loss", (int) (((ntransmitted-nreceived)*100) / ntransmitted));
    }
    printf("\n");
    if (nreceived && timing) {
        printf("round-trip (ms)  min/avg/max = %d/%ld/%d\n", tmin, tsum / nreceived, tmax);
    }
    fflush(stdout);
    exit(0);
}

void pr_pack(char *buf, int cc, struct sockaddr_in *from)
{
    int i, iphdrlen, triptime;
    struct ip *ip;    // ptr to IP header
    struct icmp *icp; // ptr to ICMP header
    long *lp;
    struct timeval tv;
    char *pr_type();

    from->sin_addr.s_addr = ntohl(from->sin_addr.s_addr);

    if (timing) {
        gettimeofday(&tv, (struct timezone *) 0);
    }

    /*
     * We have to look at the IP header, to get its length.
     * We also verify that what follows the IP header contains at
     * least an ICMP header (8 bytes minimum).
     */
    ip = (struct ip*) buf;
    iphdrlen = ip->ip_hl << 2;  // convert # 16-bit words to #bytes
    if (cc < iphdrlen + ICMP_MINLEN) {
        if (verbose) {
            printf("packet too short (%d bytes) from %s\n", cc, inet_ntoa(from->sin_addr));
        }
        return;
    }
    cc -= iphdrlen;

    icp = (struct icmp *)(buf + iphdrlen);
    if (icp->icmp_type != ICMP_ECHOREPLY) {
        /*
         * The received ICMP packet is not an echo reply.
         * If the verbose flag was set, we print the first 48 bytes
         * of the received packet as 12 longs.
         */
        if (verbose) {
            lp = (long *) buf;  // to print 12 longs
            printf("%d bytes from %s: ", cc, inet_ntoa(from->sin_addr));
            printf("icmp_type=%d (%s)\n", icp->icmp_type, pr_type(icp->icmp_type));
            for (i = 0; i < 12; i++) {
                printf("x%2.2lx: x%8.8lx\n", i*sizeof(long), *lp++);
            }
            printf("icmp_code=%d\n", icp->icmp_code);
        }
        return;
    }

    // See if we sent the packet, and if not, just ignore it.
    if (icp->icmp_id != ident) {
        return;
    }

    printf("%d bytes from %s: ", cc, inet_ntoa(from->sin_addr));
    printf("icmp_seq=%d ", icp->icmp_seq);
    if (timing) {
        // Calculate the round-trip time, and update the min/avg/max.
        tvsub(&tv, (struct timeval *) &icp->icmp_data[0]);
        triptime = tv.tv_sec * 1000 + (tv.tv_usec / 1000);

        // milliseconds
        printf("time=%d ms", triptime);
        tsum += triptime;
        if (triptime < tmin) {
            tmin = triptime;
        }
        if (triptime > tmax) {
            tmax = triptime;
        }
    }
    putchar('\n');

    // only count echo reply packets that we sent
    nreceived++;
}

/*
 * Convert an ICMP "type" field to a printable string.
 * This is called for ICMP packets that are received that are not
 * ICMP_ECHOREPLY packets.
 */
char *pr_type(int t)
{
    static char *ttab[] = {
        "Echo Reply",
        "ICMP 1",
        "ICMP 2",
        "Dest Unreachable",
        "Source Quence",
        "Redirect",
        "ICMP 6",
        "ICMP 7",
        "Echo",
        "ICMP 9",
        "ICMP 10",
        "Time Exceeded",
        "Parameter Problem",
        "Timestamp",
        "Timestamp Reply",
        "Info Request",
        "Info Reply"
    };

    if (t < 0 || t > 16) {
        return "OUT-OF-RANGE";
    }

    return ttab[t];
}

// Subtract 2 BSD timeval structs:  out = out - in.
void tvsub(struct timeval *out, struct timeval *in)
{
    // subtract microsec
    if ((out->tv_usec -= in->tv_usec) < 0) {
        out->tv_sec--;
        out->tv_usec += 1000000;
    }

    // subtract seconds
    out->tv_sec -= in->tv_sec;
}

void recv_ping()
{
    int n;
    socklen_t fromlen;
    struct sockaddr_in from;

    for ( ; ; ) {
        fromlen = sizeof(from);
        if ((n = recvfrom(sockfd, recvpack, sizeof(recvpack), 0, (struct sockaddr *) &from, &fromlen)) < 0) {
            if (errno == EINTR) {
                // this is normal
                continue;
            }
            puts("recvfrom error");
            continue;
        }

        pr_pack(recvpack, n, &from);

        /*
         * If we're only supposed to receive a certain number of
         * packets, and we've reached the limit, stop.
         */
        if (npackets && (nreceived >= npackets)) {
            // does not return
            sig_finish();
        }
    }
}

void send_ping()
{
    int i;
    struct icmp *icp; // ICMP header
    u_char *uptr;     // start of user data

     // Fill in the ICMP header.
    icp = (struct icmp *) sendpack; // pointer to ICMP header
    icp->icmp_type  = ICMP_ECHO;
    icp->icmp_code  = 0;
    icp->icmp_cksum = 0;     // init to 0, then call in_cksum() below
    icp->icmp_id    = ident; // our pid, to identify on return
    icp->icmp_seq   = ntransmitted++; // sequence number

    /*
     * Add the time stamp of when we sent it.
     * gettimeofday(2) is a BSD system call that returns the current
     * local time through its first argument.  The second argument is
     * for time zone information, which we're not interested in.
     */
    if (timing) {
        gettimeofday((struct timeval *) &sendpack[SIZE_ICMP_HDR], (struct timezone *) 0);
    }

    /*
     * And fill in the remainder of the packet with the user data.
     * We just set each byte of udata[i] to i (although this is
     * not verified when the echoed packet is received back).
     */
    uptr = &sendpack[SIZE_ICMP_HDR + SIZE_TIME_DATA];
    for (i = SIZE_TIME_DATA; i < datalen; i++) {
        *uptr++ = i;
    }

    /*
     * Compute and store the ICMP checksum (now that we've filled
     * in the entire ICMP packet).  The checksum includes the ICMP
     * header, the time stamp, and our user data.
     */
    icp->icmp_cksum = in_cksum((u_short*)icp, packsize);

     // Now send the datagram.
    i = sendto(sockfd, sendpack, packsize, 0, (struct sockaddr *) &dest, sizeof(dest));
    if (i < 0 || i != packsize)  {
        if (i < 0) {
            puts("sendto error");
        } else {
            printf("wrote %s %d bytes, return=%d\n", hostname, packsize, i);
        }
    }
}

void sig_alarm()
{
    int waittime;

    // first send another packet
    send_ping();

    if (npackets == 0 || ntransmitted < npackets) {
        /*
         * If we're not sending a fixed number of packets,
         * or if we are sending a fixed number but we've still
         * got more to send, schedule another signal for 1 second
         * from now.
         */
        alarm(1);
    } else {
        /*
         * We've sent the specified number of packets.
         * But, we can't just terminate, as there is at least one
         * packet still to be received (the one we sent at the
         * beginning of this function).
         * If we've received at least one packet already, then
         * wait for 2 times the largest round-trip time we've seen
         * so far.  Otherwise we haven't received anything yet from
         * the host we're pinging, so just wait 10 seconds.
         */
        if (nreceived) {
            waittime = 2 * tmax / 1000; // tmax is milliseconds
            if (waittime == 0) {
                waittime = 1;
            }
        } else {
            waittime = MAXWAIT;
        }

        // change the signal handler
        signal(SIGALRM, sig_finish);

        // schedule the signal
        alarm(waittime);
    }

    return;
}
