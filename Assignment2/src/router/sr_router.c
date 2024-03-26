/**********************************************************************
 * file:  sr_router.c
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */

  // print out all the header info
  print_hdrs(packet, len);

  // determine the type of packet
  uint16_t packet_type = ethertype(packet);

  // ARP packet
  if (packet_type == ethertype_arp)
  {
    sr_arp_hdr_t *arp_packet_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if *target_if = get_interface_from_ip(sr, arp_packet_hdr->ar_tip);
    // arp case 1: w/o interface in reach --> dropped
    if (target_if == NULL)
    {
      fprintf(stdout, "arp case 1: w/o interface in reach --> dropped\n");
      return;
    }

    // arp case 2: request w interface in reach --> ARP reply
    if (ntohs(arp_packet_hdr->ar_op) == arp_op_request)
    {
      fprintf(stdout, "arp case 2: request w interface in reach --> ARP reply\n");
      handle_arp_request(sr, packet, len, target_if);
      return;
    }

    // arp case 3: reply w interface in reach --> find all cached interface
    if (ntohs(arp_packet_hdr->ar_op) == arp_op_reply)
    {
      fprintf(stdout, "arp case 3: reply w interface in reach --> find all cached interface\n");
      handle_arp_reply(sr, packet);
      return;
    }
    // arp exception: w interface in reach but no reply or request opcode
    fprintf(stdout, "arp exception: w interface in reach but no reply or request opcode\n");
    return;
  }

  // ip packet
  if (packet_type == ethertype_ip)
  {

    // find corresponding interface
    sr_ip_hdr_t *ip_packet_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if *target_if = get_interface_from_ip(sr, ip_packet_hdr->ip_dst);
    struct sr_if *iface = sr_get_interface(sr, interface);

    if (target_if == NULL)
    {
      // forward packet

      // 1. decrement TTL

      // Find match for the destination IP address in the routing table
      struct sr_rt *rt_walker = sr->routing_table;
      while (rt_walker->next)
      {
        if (rt_walker->dest.s_addr == ip_packet_hdr->ip_dst)
        {
          // ip case 1: ttl expired --> send back TIME_EXCEED icmp
          ip_packet_hdr->ip_ttl--;
          if (ip_packet_hdr->ip_ttl == 0)
          {
            fprintf(stdout, "ip case 1: ttl expired --> send back TIME_EXCEED icmp\n");
            handle_ip_time_exceed(sr, packet, iface);
            return;
          }
          // find next-hop mac address
          struct sr_arpentry *next_hop_mac = sr_arpcache_lookup(
              &(sr->cache), ip_packet_hdr->ip_dst);
          if (next_hop_mac)
          {
            // ip case 2: ip packet w. router interface w. entry in table w. MAC --> forwarding
            fprintf(stdout, "ip case 2: ip packet w. router interface w. entry in table w. MAC --> forwarding\n");
            handle_ip_forwarding(sr, packet, len, sr_get_interface(sr, rt_walker->interface), next_hop_mac);
            return;
          }
          // ip case 3: ip packet w. router interface w. entry in table w/o MAC --> send ARP request + cache packet
          fprintf(stdout, "ip case 3: ip packet w. router interface w. entry in table w/o MAC --> send ARP request + cache packet\n");
          struct sr_arpreq *cur_request = sr_arpcache_queuereq(&(sr->cache),
                                                               ip_packet_hdr->ip_dst,
                                                               packet, len, rt_walker->interface);
          handle_ip_cached_packet(sr, cur_request);
          return;
        }
        rt_walker = rt_walker->next;
      }
      // not found

      // ip case 6: ip packet w/o router interface w/o entry in table  --> send net-unreachable ICMP packet
      fprintf(stdout, "ip case 6: ip packet w. router interface w/o entry in table  --> send net-unreachable ICMP packet\n");
      handle_ip_net_unreachable(sr, packet, iface);
      return;
    }

    fprintf(stdout, "found target interface\n");
    fprintf(stdout, "interface name: %s \n", target_if->name);

    if (ip_packet_hdr->ip_p == ip_protocol_icmp)
    {
      sr_icmp_hdr_t *icmp_packet_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      // ip case 7: ip packet w router interface w icmp w type 8 echo --> send echo reply
      fprintf(stdout, "ip case 7: ip packet w router interface w type 8 echo  --> send echo reply\n");
      if (icmp_packet_hdr->icmp_type == ICMP_ECHO)
      {
        handle_ip_echoreply(sr, packet, len, target_if, iface);
        return;
      }

      // ip case 8: ip packet w router interface w icmp w/o type 8 echo --> dropped
      fprintf(stdout, "ip case 8: ip packet w router interface w icmp w/o type 8 echo --> dropped\n");
      return;
    }

    // ip case 9: ip packet w router interface w/o icmp protocol --> send port unreachable
    fprintf(stdout, "ip case 9: ip packet w router interface w/o icmp protocol --> send port unreachable\n");
    handle_ip_port_unreachable(sr, packet, target_if, iface);
    return;
  }

  // ethenet exception: unrecognizable ethertype --> dropped
  fprintf(stdout, "ethernet exception: unrecognizable ethertype --> dropped\n");
  return;
} /* end sr_handlepacket */

/* Add any additional helper methods here & don't forget to also declare
them in sr_router.h.


If you use any of these methods in sr_arpcache.c, you must also forward declare
them in sr_arpcache.h to avoid circular dependencies. Since sr_router
already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */

void modify_ethernet_hdr(sr_ethernet_hdr_t *reply_ether_hdr,
                         sr_ethernet_hdr_t *src_ether_hdr,
                         struct sr_if *interface, uint16_t ether_type)
{
  const unsigned char broadcast_mac[ETH_ALEN] = BROADCAST_MAC;
  if (src_ether_hdr)
  {
    memcpy(reply_ether_hdr->ether_dhost, src_ether_hdr->ether_shost, ETH_ALEN);
  }
  else
  {
    memcpy(reply_ether_hdr->ether_dhost, &(broadcast_mac), ETH_ALEN);
  }
  memcpy(reply_ether_hdr->ether_shost, interface->addr, ETH_ALEN);
  reply_ether_hdr->ether_type = htons(ether_type);
}

void modify_arp_hdr(sr_arp_hdr_t *reply_arp_hdr,
                    sr_arp_hdr_t *src_arp_hdr, sr_ip_hdr_t *src_ip_hdr, struct sr_if *interface,
                    unsigned short arp_opcode)
{
  const unsigned char broadcast_mac[ETH_ALEN] = BROADCAST_MAC;
  if (src_ip_hdr)
  {
    reply_arp_hdr->ar_hrd = htons(1);
    reply_arp_hdr->ar_pro = htons(2048);
    reply_arp_hdr->ar_hln = 6;
    reply_arp_hdr->ar_pln = 4;
    memcpy(reply_arp_hdr->ar_tha, &(broadcast_mac), ETH_ALEN);
    reply_arp_hdr->ar_tip = src_ip_hdr->ip_dst;
  }
  else
  {
    memcpy(reply_arp_hdr, src_arp_hdr, sizeof(sr_arp_hdr_t));
    memcpy(reply_arp_hdr->ar_tha, src_arp_hdr->ar_sha, ETH_ALEN);
    reply_arp_hdr->ar_tip = src_arp_hdr->ar_sip;
  }
  reply_arp_hdr->ar_op = htons(arp_opcode);
  memcpy(reply_arp_hdr->ar_sha, interface->addr, ETH_ALEN);
  reply_arp_hdr->ar_sip = interface->ip;
}

void modify_ip_hdr(sr_ip_hdr_t *reply_ip_hdr,
                   sr_ip_hdr_t *src_ip_hdr, struct sr_if *interface, int not_echo_reply)
{
  if (src_ip_hdr)
  {
    memcpy((uint8_t *)reply_ip_hdr, (uint8_t *)src_ip_hdr, sizeof(sr_ip_hdr_t));
    reply_ip_hdr->ip_sum = 0;
    reply_ip_hdr->ip_src = interface->ip;
    reply_ip_hdr->ip_dst = src_ip_hdr->ip_src;
    reply_ip_hdr->ip_p = ip_protocol_icmp;
    reply_ip_hdr->ip_ttl = INIT_TTL;
    if (not_echo_reply)
    {
      reply_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    }
    reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, sizeof(sr_ip_hdr_t));
  }
}

void modify_icmp_hdr(sr_icmp_hdr_t *reply_icmp_hdr,
                     sr_icmp_hdr_t *src_icmp_hdr,
                     uint8_t icmp_type,
                     uint8_t icmp_code,
                     uint8_t *packet)
{
  if (src_icmp_hdr)
  {
    memcpy((uint8_t *)reply_icmp_hdr, (uint8_t *)src_icmp_hdr, sizeof(sr_icmp_hdr_t));
  }
  else if (packet)
  {
    memcpy(((uint8_t *)reply_icmp_hdr) + 8, (uint8_t *)(packet + sizeof(sr_ethernet_hdr_t)), 28);
  }
  reply_icmp_hdr->icmp_sum = 0;
  reply_icmp_hdr->icmp_type = icmp_type;
  reply_icmp_hdr->icmp_code = icmp_code;
  reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, sizeof(sr_icmp_hdr_t));
}

void modify_remaining_bit(uint8_t *reply_packet, uint8_t *src_packet,
                          unsigned int header_len, unsigned int expected_len)
{
  if (header_len < expected_len)
  {
    memcpy(reply_packet + header_len, src_packet + header_len, (expected_len - header_len));
  }
}

void send_packet_with_status(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *interface)
{
  int reply_code = sr_send_packet(sr, packet, len, interface->name);
  if (reply_code == -1)
  {
    fprintf(stdout, "reply message send fails\n");
  }
  else
  {
    fprintf(stdout, "reply message send suceeds\n");
  }
}

void handle_arp_request(struct sr_instance *sr,
                        uint8_t *packet /* lent */,
                        unsigned int len,
                        struct sr_if *target_if)
{
  uint8_t *reply_packet = (uint8_t *)malloc(PACKET_DUMP_SIZE);

  // set ethernet header
  sr_ethernet_hdr_t *reply_ether_hdr = (sr_ethernet_hdr_t *)reply_packet;
  modify_ethernet_hdr(reply_ether_hdr, (sr_ethernet_hdr_t *)packet, target_if, ethertype_arp);

  // set arp header
  sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
  modify_arp_hdr(reply_arp_hdr, (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)),
                 NULL, target_if, arp_op_reply);

  modify_remaining_bit(reply_packet, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), len);

  print_hdrs(reply_packet, len);

  send_packet_with_status(sr, reply_packet, len, target_if);
  free(reply_packet);
}

void handle_arp_reply(struct sr_instance *sr, uint8_t *packet)
{
  sr_arp_hdr_t *arp_packet_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  fprintf(stdout, "ip address requested:\n");
  print_addr_ip_int(ntohl(arp_packet_hdr->ar_sip));
  fprintf(stdout, "found corresponding MAC:\n");
  print_addr_eth(arp_packet_hdr->ar_sha);
  struct sr_arpreq *arpreq_for_reply = sr_arpcache_insert(&(sr->cache),
                                                          arp_packet_hdr->ar_sha,
                                                          arp_packet_hdr->ar_sip);
  struct sr_packet *cur_packet = arpreq_for_reply->packets;
  uint8_t *reply_packet;
  struct sr_if *interface;

  while (cur_packet)
  {
    reply_packet = cur_packet->buf;
    interface = sr_get_interface(sr, cur_packet->iface);

    modify_ethernet_hdr((sr_ethernet_hdr_t *)reply_packet, (sr_ethernet_hdr_t *)packet,
                        sr_get_interface(sr, cur_packet->iface), ntohs(((sr_ethernet_hdr_t *)reply_packet)->ether_type));

    if (ntohs(((sr_ethernet_hdr_t *)reply_packet)->ether_type) == ethertype_ip)
    {
      sr_ip_hdr_t *reply_packet_ip_hdr = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
      reply_packet_ip_hdr->ip_sum = 0;
      reply_packet_ip_hdr->ip_ttl--;
      reply_packet_ip_hdr->ip_sum = cksum(reply_packet_ip_hdr, sizeof(sr_ip_hdr_t));
    }

    print_hdrs(reply_packet, cur_packet->len);
    send_packet_with_status(sr, reply_packet, cur_packet->len, interface);
    cur_packet = cur_packet->next;
  }
  sr_arpreq_destroy(&(sr->cache), arpreq_for_reply);
}

void handle_ip_time_exceed(struct sr_instance *sr,
                           uint8_t *packet, struct sr_if *interface)
{
  uint8_t *reply_packet = (uint8_t *)malloc(PACKET_DUMP_SIZE);
  unsigned int reply_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);

  // set ethernet header
  modify_ethernet_hdr((sr_ethernet_hdr_t *)reply_packet, (sr_ethernet_hdr_t *)packet,
                      interface, ethertype_ip);

  // set ip header
  modify_ip_hdr((sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t)),
                (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)),
                interface, 1);

  // set icmp header
  modify_icmp_hdr((sr_icmp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)),
                  NULL, ICMP_TIME_EXCEEDED, 0, packet);

  print_hdrs(reply_packet, reply_packet_len);

  send_packet_with_status(sr, reply_packet, reply_packet_len, interface);
  free(reply_packet);
}

void handle_ip_forwarding(struct sr_instance *sr,
                          uint8_t *packet, unsigned int len, struct sr_if *interface,
                          struct sr_arpentry *next_hop_mac)
{
  // if found, forward IP packet
  uint8_t *reply_packet = (uint8_t *)malloc(PACKET_DUMP_SIZE);
  memcpy(reply_packet, packet, len);

  // set ethernet header
  sr_ethernet_hdr_t *reply_ether_hdr = (sr_ethernet_hdr_t *)reply_packet;
  memcpy(reply_ether_hdr->ether_shost, interface->addr, ETH_ALEN);
  memcpy(reply_ether_hdr->ether_dhost, next_hop_mac->mac, ETH_ALEN);

  if (ntohs(((sr_ethernet_hdr_t *)reply_packet)->ether_type) == ethertype_ip)
  {
    sr_ip_hdr_t *reply_packet_ip_hdr = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
    reply_packet_ip_hdr->ip_sum = 0;
    reply_packet_ip_hdr->ip_ttl--;
    reply_packet_ip_hdr->ip_sum = cksum(reply_packet_ip_hdr, sizeof(sr_ip_hdr_t));
  }

  print_hdrs(reply_packet, len);

  send_packet_with_status(sr, reply_packet, len, interface);
  free(reply_packet);
}

void handle_ip_cached_packet(struct sr_instance *sr, struct sr_arpreq *cur_request)
{
  struct sr_packet *cur_packet = cur_request->packets;
  struct sr_if *interface = sr_get_interface(sr, cur_packet->iface);
  if (difftime(time(NULL), cur_request->sent) > 1.0)
  {
    if (cur_request->times_sent >= 5)
    {
      // ip case 4: arp request sent 5 times w/o response --> send ICMP host unreachable
      fprintf(stdout, "ip case 4: arp request sent 5 times w/o response --> send ICMP host unreachable\n");
      // send unreachable
      uint8_t *reply_packet = (uint8_t *)malloc(PACKET_DUMP_SIZE);
      unsigned int reply_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
                                      sizeof(sr_icmp_hdr_t);

      // set ethernet headers
      modify_ethernet_hdr((sr_ethernet_hdr_t *)reply_packet, (sr_ethernet_hdr_t *)(cur_packet->buf),
                          interface, ethertype_ip);

      // set ip header
      modify_ip_hdr((sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t)),
                    (sr_ip_hdr_t *)(cur_packet->buf + sizeof(sr_ethernet_hdr_t)), interface, 1);

      // set icmp header
      modify_icmp_hdr((sr_icmp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)),
                      NULL, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, cur_packet->buf);

      print_hdrs(reply_packet, reply_packet_len);
      // send packet
      send_packet_with_status(sr, reply_packet, reply_packet_len, interface);
      free(reply_packet);
      // destroy packet
      sr_arpreq_destroy(&(sr->cache), cur_request);
      return;
    }

    // ip case 5: send arp request per 1 seconds
    fprintf(stdout, "ip case 5: send arp request per 1 seconds\n");
    uint8_t *request_packet = (uint8_t *)malloc(PACKET_DUMP_SIZE);
    unsigned int request_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);

    // set ethernet header
    modify_ethernet_hdr((sr_ethernet_hdr_t *)request_packet, NULL,
                        interface, ethertype_arp);

    // set arp header
    modify_arp_hdr((sr_arp_hdr_t *)(request_packet + sizeof(sr_ethernet_hdr_t)), NULL,
                   (sr_ip_hdr_t *)(cur_packet->buf + sizeof(sr_ethernet_hdr_t)), interface, arp_op_request);

    print_hdrs(request_packet, request_packet_len);

    send_packet_with_status(sr, request_packet, request_packet_len, interface);

    cur_request->sent = time(NULL);
    cur_request->times_sent++;
    return;
  }
}

void handle_ip_net_unreachable(struct sr_instance *sr,
                               uint8_t *packet, struct sr_if *interface)
{
  uint8_t *reply_packet = (uint8_t *)malloc(PACKET_DUMP_SIZE);
  unsigned int reply_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);

  // set ethernet header
  modify_ethernet_hdr((sr_ethernet_hdr_t *)reply_packet, (sr_ethernet_hdr_t *)packet, interface, ethertype_ip);

  // set ip header
  modify_ip_hdr((sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t)),
                (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)), interface, 1);

  // set icmp header
  modify_icmp_hdr((sr_icmp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)),
                  NULL, ICMP_DEST_UNREACH, ICMP_NET_UNREACH, packet);

  print_hdrs(reply_packet, reply_packet_len);

  send_packet_with_status(sr, reply_packet, reply_packet_len, interface);
  free(reply_packet);
}

void handle_ip_echoreply(struct sr_instance *sr, uint8_t *packet,
                         unsigned int len, struct sr_if *interface, struct sr_if *send_interface)
{
  uint8_t *reply_packet = (uint8_t *)malloc(PACKET_DUMP_SIZE);
  // memcpy(reply_packet, packet, len);
  // set ethernet header
  modify_ethernet_hdr((sr_ethernet_hdr_t *)reply_packet, (sr_ethernet_hdr_t *)packet,
                      send_interface, ethertype_ip);

  // set ip header
  modify_ip_hdr((sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t)),
                (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)), interface, 0);

  // set icmp header
  modify_icmp_hdr((sr_icmp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)),
                  (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)),
                  ICMP_ECHOREPLY, 0, NULL);

  // set remaining bit if there are
  modify_remaining_bit(reply_packet, packet,
                       sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t), len);

  print_hdrs(reply_packet, len);

  send_packet_with_status(sr, reply_packet, len, send_interface);
  free(reply_packet);
}

void handle_ip_port_unreachable(struct sr_instance *sr, uint8_t *packet,
                                struct sr_if *interface, struct sr_if *send_interface)
{
  uint8_t *reply_packet = (uint8_t *)malloc(PACKET_DUMP_SIZE);
  unsigned int reply_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);

  // set ethernet header
  modify_ethernet_hdr((sr_ethernet_hdr_t *)reply_packet, (sr_ethernet_hdr_t *)packet, send_interface, ethertype_ip);

  // set ip header
  modify_ip_hdr((sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t)),
                (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)), interface, 1);

  // set icmp header
  modify_icmp_hdr((sr_icmp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)),
                  NULL, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, packet);

  print_hdrs(reply_packet, reply_packet_len);

  send_packet_with_status(sr, reply_packet, reply_packet_len, send_interface);
  free(reply_packet);
}