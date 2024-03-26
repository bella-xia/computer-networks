# README for Assignment 2: Router

Name: Bella Xia

JHED: zxia15

---

**DESCRIBE YOUR CODE AND DESIGN DECISIONS HERE**

This will be worth 10% of the assignment grade.

Some guiding questions:

- What files did you modify (and why)?
- What helper method did you write (and why)?
- What logic did you implement in each file/method?
- What problems or challenges did you encounter?

Implementations and Logics:
I modifed three files in total: sr_arpcache.c, sr_router.c and sr_router.h. Because sr_router.h only changes to declare the new helper functions implemented in sr_router.c, so the major changes to be discussed will be in the two c scripts.

1. I make the majority of the changes in sr_router.c. In general, the only core function that is modified is

void sr_handlepacket(struct sr_instance *sr, uint8_t *packet, unsigned int len, char interface)

which is the function that gets called whenever a packet is received by the router. Since the handling of the packet goes through a very long pipeline, I split the process into multiple steps and each case for each step receives its corresponding helper function. The general pipeline of implementation is as follows:

Step 1. a uint8_t packet received together with its length

Step 2. check its Ethernet Header

--> If has ethertype of ARP
Step 2.1-1. check its ARP Header

    --> If has opcode of ARP request
        Step 2.1-1-1. check the IP address for the request

        --> If not a router interface
            arp case 1: w/o interface in reach --> dropped

        --> If is a router interface
            arp case 2: request w interface in reach --> construct ARP reply

            this is completed using the helper function
            void handle_arp_request(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *target_if);

    --> If has opcode of ARP reply
        arp case 3: reply w interface in reach --> find all cached packet

        this is completed using the helper function
        void handle_arp_reply(struct sr_instance *sr, uint8_t *packet);

--> If has ethertype of IP
Step 2.1-2. check its IP Header

    --> If the destination IP address is not within the router interface

        --> If the destination IP address is within the routing table
            Step 2.1-2-1-1. decrement its TTL by 1 and check its TTL

            --> If TTL expires
                ip case 1: ttl expired --> send back TIME_EXCEED icmp

                this is completed using the helper function
                void handle_ip_time_exceed(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface);

            --> If TTL has not expired
                Step 2.1-2-1-1-2. Check whether arpcache contains the corresponding MAC address for the IP destination

                --> If contains the MAC address
                    ip case 2: ip packet w. router interface w. entry in table w. MAC --> forwarding

                    this is completed using the helper function
                    void handle_ip_forwarding(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *interface, struct sr_arpentry *next_hop_mac);

                --> If does not contain
                    ip case 3: ip packet w. router interface w. entry in table w/o MAC --> send ARP request + cache packet

                    this is completed using the helper function
                    void handle_ip_cached_packet(struct sr_instance *sr, struct sr_arpreq *cur_request);

                    which would also be responsible for re-sending the cached packet ARP request per second as well as sending HOST UNREACHABLE at the end of 5 such sends


        --> If the destination IP address not in the routing table
            ip case 6: ip packet w/o router interface w/o entry in table  --> send net-unreachable ICMP packet

            ths is completed using the helper function
            void handle_ip_net_unreachable(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface);

    --> If the destination IP address is within the router interface
        Step 2.1-2-2.1. check the IP protocol of the packet

            --> If protocol is ICMP
                Step 2.1-2-2.1-1. check its ICMP header

                --> IF is type 8 (echo)
                    ip case 7: ip packet w router interface w icmp w type 8 echo --> send echo reply

                    this is completed using the helper function
                    void handle_ip_echoreply(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *interface, struct sr_if *send_interface);

                --> If has other type
                    ip case 8: ip packet w router interface w icmp w/o type 8 echo --> dropped

            --> If protocol is not ICMP
                    ip case 9: ip packet w router interface w/o icmp protocol --> send port unreachable

                    this is completed using the helper function
                    void handle_ip_port_unreachable(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface, struct sr_if *send_interface);

--> If has ethertype of neither
ethernet case 1: unrecognizable ethertype --> Drop Packet

Additionally, in order to help with the repetitions in rewriting packets, I implemented general helper functions

writing into packet:
void modify_ethernet_hdr(sr_ethernet_hdr_t *reply_ether_hdr, sr_ethernet_hdr_t *src_ether_hdr, struct sr_if \*interface, uint16_t ether_type);

void modify_arp_hdr(sr_arp_hdr_t *reply_arp_hdr, sr_arp_hdr_t *src_arp_hdr, sr_ip_hdr_t *src_ip_hdr, struct sr_if *interface, unsigned short arp_opcode);

void modify_ip_hdr(sr_ip_hdr_t *reply_ip_hdr, sr_ip_hdr_t *src_ip_hdr, struct sr_if \*interface, int not_echo_reply);

void modify_icmp_hdr(sr_icmp_hdr_t *reply_icmp_hdr, sr_icmp_hdr_t *src_icmp_hdr, uint8_t icmp_type, uint8_t icmp_code, uint8_t \*packet);

void modify_remaining_bit(uint8_t *reply_packet, uint8_t *src_packet, unsigned int header_len, unsigned int expected_len);

sending packet:
void send_packet_with_status(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if \*interface);

which can called respectively in the cases above.

2. My changes to sr_arpcache.c is more subtle. In general, I only modified two functions:

2.1 void sr_arpcache_sweepreqs(struct sr_instance \*sr)

In this function, I iterated over all the requests still stored in the cache of the sr instance. For each request, the helper function handle_arpreq is called

2.2 void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *request)

Because this function encompass the two situations:

ip case 4: arp request sent 5 times w/o response --> send ICMP host unreachable
ip case 5: send arp request per 1 seconds

which are closely aligned with the previous case

ip case 3: ip packet w. router interface w. entry in table w/o MAC --> send ARP request + cache packet

in sr_router.c. Therefore, one single helper function

void handle_ip_cached_packet(struct sr_instance *sr, struct sr_arpreq *cur_request);

is used for all three cases. And so in handle_arpreq the helper function handle_ip_cached_packet is evoked with the corresponding arguments

Challenges:
Two biggest challenges I have encountered are

1. finding the corresponding interface for packet deliveries

   At first I am confused about particularly the router, which has three interface altogether. I constantly use the wrong interface in communicating with the servers and clients. It takes me some effort to be able to differentiate between the interface where the packet is received, the router interface a packet is addressing, and the interface for corresponding server/client deliveries in the routing table.

2. Correct header information

   This is particularly challenging for me for regions that are not eplicitly specified, e.g. a lot of the IP headers for ICMP type 3 / type 11 packets that needs to be filled without prototype to be copied from. I spent a lot of time understanding the debugging each header info so that the packet can be delivered correctly.
