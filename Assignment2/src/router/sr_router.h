/*-----------------------------------------------------------------------------
 * File: sr_router.h
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ##args)
#define DebugMAC(x)                        \
  do                                       \
  {                                        \
    int ivyl;                              \
    for (ivyl = 0; ivyl < 5; ivyl++)       \
      printf("%02x:",                      \
             (unsigned char)(x[ivyl]));    \
    printf("%02x", (unsigned char)(x[5])); \
  } while (0)
#else
#define Debug(x, args...) \
  do                      \
  {                       \
  } while (0)
#define DebugMAC(x) \
  do                \
  {                 \
  } while (0)
#endif

#define INIT_TTL 64
#define PACKET_DUMP_SIZE 1024
#define BROADCAST_MAC {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
  int sockfd;        /* socket to server */
  char user[32];     /* user name */
  char host[32];     /* host name */
  char template[30]; /* template name if any */
  unsigned short topo_id;
  struct sockaddr_in sr_addr;  /* address to server */
  struct sr_if *if_list;       /* list of interfaces */
  struct sr_rt *routing_table; /* routing table */
  struct sr_arpcache cache;    /* ARP cache */
  pthread_attr_t attr;
  FILE *logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance *sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance *, uint8_t *, unsigned int, const char *);
int sr_connect_to_server(struct sr_instance *, unsigned short, char *);
int sr_read_from_server(struct sr_instance *);

/* -- sr_router.c -- */
void sr_init(struct sr_instance *);
void sr_handlepacket(struct sr_instance *, uint8_t *, unsigned int, char *);

/* Add additional helper method declarations here! */

// writing into packet
void modify_ethernet_hdr(sr_ethernet_hdr_t *reply_ether_hdr, sr_ethernet_hdr_t *src_ether_hdr, struct sr_if *interface, uint16_t ether_type);

void modify_arp_hdr(sr_arp_hdr_t *reply_arp_hdr, sr_arp_hdr_t *src_arp_hdr, sr_ip_hdr_t *src_ip_hdr, struct sr_if *interface, unsigned short arp_opcode);

void modify_ip_hdr(sr_ip_hdr_t *reply_ip_hdr, sr_ip_hdr_t *src_ip_hdr, struct sr_if *interface);

void modify_icmp_hdr(sr_icmp_hdr_t *reply_icmp_hdr, sr_icmp_hdr_t *src_icmp_hdr, uint8_t icmp_type, uint8_t icmp_code, uint8_t *packet);

void modify_remaining_bit(uint8_t *reply_packet, uint8_t *src_packet, unsigned int header_len, unsigned int expected_len);
// sending packet
void send_packet_with_status(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *interface);

// handling different cases

// arp case 2: request w interface in reach-- > ARP reply
void handle_arp_request(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *target_if);

// arp case 3: reply w interface in reach --> find all cached interface
void handle_arp_reply(struct sr_instance *sr, uint8_t *packet);

// ip case 1: ttl expired --> send back TIME_EXCEED icmp
void handle_ip_time_exceed(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface);

// ip case 2: ip packet w. router interface w. entry in table w. MAC --> forwarding
void handle_ip_forwarding(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *interface, struct sr_arpentry *next_hop_mac);

// ip case 3: ip packet w. router interface w. entry in table w/o MAC --> send ARP request + cache packet
// ip case 4: arp request sent 5 times w/o response --> send ICMP host unreachable
// ip case 5: send arp request per 1 seconds
void handle_ip_cached_packet(struct sr_instance *sr, struct sr_arpreq *cur_request);

// ip case 6: ip packet w. router interface w/o entry in table --> send net-unreachable ICMP packet
void handle_ip_net_unreachable(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface);

// ip case 7: ip packet w router interface w icmp w type 8 echo --> send echo reply
void handle_ip_echoreply(struct sr_instance *sr, uint8_t *packet,
                         unsigned int len, struct sr_if *interface, struct sr_if *send_interface);

// ip case 9: ip packet w router interface w/o icmp protocol --> send port unreachables
void handle_ip_port_unreachable(struct sr_instance *sr, uint8_t *packet,
                                struct sr_if *interface, struct sr_if *send_interface);

/* -- sr_if.c -- */
struct sr_if *sr_get_interface(struct sr_instance *, const char *);
struct sr_if *get_interface_from_ip(struct sr_instance *, uint32_t);
struct sr_if *get_interface_from_eth(struct sr_instance *, uint8_t *);
void sr_add_interface(struct sr_instance *, const char *);
void sr_set_ether_ip(struct sr_instance *, uint32_t);
void sr_set_ether_addr(struct sr_instance *, const unsigned char *);
void sr_print_if_list(struct sr_instance *);

#endif /* SR_ROUTER_H */
