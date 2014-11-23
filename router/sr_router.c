/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


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
void make_and_send_icmp(struct sr_instance* sr, sr_ip_hdr_t* ip_packet, 
    int icmp_type, int icmp_code, char* interface);

void send_packet(struct sr_instance* sr, uint8_t* packet, unsigned int packet_len,
 uint32_t target, enum sr_ethertype type, int rt_icmp_not_found);

void sr_init(struct sr_instance* sr)
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


/*---------------------------------------------------------------------
 * Method: send_arp_reply
 * Scope:  Global
 *
 * Constructs an ARP reply to an ARP request and sends it.
 *
 *---------------------------------------------------------------------*/
void send_arp_reply(struct sr_instance* sr, sr_arp_hdr_t* arp_header,
                    char* interface, uint8_t * packet, unsigned int len) {
        
    struct sr_if* interface_sr_if = sr_get_interface(sr, interface);
    sr_arp_hdr_t* arp_reply_header =
    (struct sr_arp_hdr*) malloc(sizeof(struct sr_arp_hdr));
    
    arp_reply_header->ar_hrd = htons(arp_hrd_ethernet);
    arp_reply_header->ar_pro = htons(ethertype_ip);
    arp_reply_header->ar_hln = ETHER_ADDR_LEN;
    arp_reply_header->ar_pln = sizeof(uint32_t);
    arp_reply_header->ar_op = htons(arp_op_reply);
    arp_reply_header->ar_sip = interface_sr_if->ip;
    arp_reply_header->ar_tip = arp_header->ar_sip;
    memcpy(arp_reply_header->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
    memcpy(arp_reply_header->ar_sha, interface_sr_if->addr, ETHER_ADDR_LEN);
    
    /* construct frame and send packet */

    sr_ethernet_hdr_t* ether_header =  (sr_ethernet_hdr_t*)packet;

    memcpy(ether_header->ether_dhost, ether_header->ether_shost, ETHER_ADDR_LEN);
    memcpy(ether_header->ether_shost, interface_sr_if->addr, ETHER_ADDR_LEN);
    
    
    memcpy(packet, ether_header, sizeof(struct sr_ethernet_hdr));
    memcpy(packet + sizeof(struct sr_ethernet_hdr),
           arp_reply_header, sizeof(struct sr_arp_hdr));
    
    /* print_hdrs(packet, len); */
    sr_send_packet(sr, packet, len, interface);
    
    free(arp_reply_header);
    
    
    
}

struct sr_rt* longest_prefix_match(struct sr_instance* sr, uint32_t ip_dst){
    struct sr_rt* cur = sr->routing_table;
    struct sr_rt* longest = NULL;
    unsigned long match_len = 0;
    struct in_addr addr;
    addr.s_addr = ip_dst;

    while(cur != NULL) {
        printf(" matching adddresses cur addr %d \n", (cur->dest.s_addr & cur->mask.s_addr));
        printf(" matching adddresses comp addr %d \n", (addr.s_addr & cur->mask.s_addr));
        if (((cur->dest.s_addr & cur->mask.s_addr) ==
             (addr.s_addr & cur->mask.s_addr)) & (match_len <= cur->mask.s_addr)){
            
            match_len = cur->mask.s_addr;
            longest = cur;
            printf(" Found a match\n");
        }
        cur = cur->next;
    }
    return longest;
}

/* returns 1 if target_ip matches any ip's in if_list */
int is_in_interface_lst(struct sr_instance* sr, uint32_t ip_dst){
    
    struct sr_if* cur = sr->if_list;
    
    while (cur != NULL) {
        if (cur->ip == ip_dst) {
            return 1;
        }
        cur = cur->next;
    }
    return 0;
}

/* new helper functions */

void make_and_send_icmp(struct sr_instance* sr, sr_ip_hdr_t* ip_packet,
int icmp_type, int icmp_code, char* interface) {

    printf("***** SENDING ICMP OF TYPE %d \n", icmp_type);
    if (icmp_type == 3 || icmp_type == 11) {
        struct sr_icmp_t3_hdr* icmp_header = 
        (struct sr_icmp_t3_hdr*) malloc(sizeof(struct sr_icmp_t3_hdr)); 

        struct sr_ip_hdr* ip_header = 
        (struct sr_ip_hdr*) malloc(sizeof(struct sr_ip_hdr));

        icmp_header->icmp_type = icmp_type;
        icmp_header->icmp_code = icmp_code;
        icmp_header->icmp_sum = 0;

        icmp_header->unused = 0;
        memcpy(icmp_header->data, ip_packet, ICMP_DATA_SIZE);
        ip_header->ip_dst = ip_packet->ip_src;
        ip_header->ip_id = ip_packet->ip_id;
        ip_header->ip_p = ip_protocol_icmp;
        ip_header->ip_tos = 0;
        ip_header->ip_off = htons(IP_DF);
        ip_header->ip_ttl = 100;

        /*
        printf("@@@@@@@ SIZES 4*ip_hl is %d, sizeof is %lu \n", ip_header->ip_hl, sizeof(struct sr_ip_hdr));
        printf("%d      %lu \n", ntohs(ip_packet->ip_len) ,sizeof(struct sr_icmp_t3_hdr));
        */

        unsigned int len = 4*ip_header->ip_hl + sizeof(struct sr_icmp_t3_hdr);

        struct sr_if *inf;
        struct sr_rt* rt_entry = longest_prefix_match(sr, ip_header->ip_dst);
        if (rt_entry == NULL) {
            /* ignore */
            return;
        }
        inf = sr_get_interface(sr, (const char*)rt_entry->interface);
    
        /*        print_addr_ip_int(ntohl(inf->ip)); */

        ip_header->ip_src = inf->ip;
        ip_header->ip_len = htons(len);
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum(ip_header, 4*ip_header->ip_hl);

        icmp_header->icmp_sum = cksum(icmp_header, 4*ip_header->ip_hl);

        uint8_t* packet = malloc(len);

        memcpy(packet, ip_header, 4*ip_header->ip_hl);
        memcpy(packet + 4*ip_header->ip_hl, icmp_header,
         sizeof(struct sr_icmp_t3_hdr));

        /* send_icmp_packet(sr, packet, len, ip_header->ip_dst); */
        send_packet(sr, packet, len, ip_packet->ip_src, ethertype_ip, 0);

    } else if (icmp_type == 0) {
        /* echo reply */ 
        struct sr_icmp_hdr* icmp_header;
        uint16_t ip_len = ntohs(ip_packet->ip_len);

        uint32_t src = ip_packet->ip_src;
        uint32_t dest = ip_packet->ip_dst;
        ip_packet->ip_src = dest;
        ip_packet->ip_dst = src;

        icmp_header = (sr_icmp_hdr_t*) ((uint8_t*)ip_packet + 4*ip_packet->ip_hl);
        icmp_header->icmp_type = icmp_type;
        icmp_header->icmp_type = icmp_code;

        uint8_t* packet = malloc(ip_len);
        icmp_header->icmp_sum = 0;
        ip_packet->ip_sum = 0;
        ip_packet->ip_sum = cksum(ip_packet, 4*ip_packet->ip_hl);
        icmp_header->icmp_sum = cksum(icmp_header, ip_len - 4*ip_packet->ip_hl);

        memcpy(packet, ip_packet, ip_len);

        printf(" ******************* $$$$$$$$ ICMP SENDING ECHO REPLY 0,0 \n");

        send_packet(sr, (uint8_t*)ip_packet, ip_len, src, ethertype_ip, 2);

        /* send_icmp_packet(sr, packet, len, dest);*/
    }
}

void send_packet(struct sr_instance* sr, uint8_t* packet, unsigned int packet_len,
 uint32_t target, enum sr_ethertype type, int rt_icmp_not_found) {

    struct sr_rt* rt_entry = longest_prefix_match(sr, target);

    if (rt_entry == NULL) {
        if (rt_icmp_not_found == 1)
            make_and_send_icmp(sr, (sr_ip_hdr_t*) packet, 3, 0, NULL);
        return;
    }

    struct sr_if* iface = sr_get_interface(sr, rt_entry->interface);

    struct sr_arpentry* arp_item = sr_arpcache_lookup(&sr->cache, rt_entry->gw.s_addr);

    if (arp_item || type == ethertype_arp) {
        struct sr_ethernet_hdr ether_header;

        ether_header.ether_type = htons(type);

        if (type == ethertype_arp && (((struct sr_arp_hdr *)packet)->ar_op == htons(arp_op_request))) {
            memset(ether_header.ether_dhost, 255, ETHER_ADDR_LEN);
        } else if(arp_item){
            memcpy(ether_header.ether_dhost, arp_item->mac, ETHER_ADDR_LEN);
        }

        memcpy(ether_header.ether_shost, iface->addr, ETHER_ADDR_LEN);

        uint8_t* ether_packet = malloc(packet_len + sizeof(struct sr_ethernet_hdr));
        memcpy(ether_packet, &ether_header, sizeof(struct sr_ethernet_hdr));
        memcpy(ether_packet + sizeof(struct sr_ethernet_hdr), packet, packet_len);

        printf("interace name %s\n", rt_entry->interface);
        print_hdrs(ether_packet, packet_len + sizeof(struct sr_ethernet_hdr));
        sr_send_packet(sr, ether_packet, packet_len + sizeof(struct sr_ethernet_hdr), rt_entry->interface);
        free(ether_packet);
    } else {
        /* printf("*********** NO ARP CACHE MISSED! \n"); */
        uint8_t* ip_packet_copy = malloc(packet_len);
        memcpy(ip_packet_copy, packet, packet_len);
        if (rt_icmp_not_found == 2) {
            printf(" 2 SENDING PACKET !!!!!!!!!!!!!!!!!!!! \n");
            print_hdr_ip(ip_packet_copy);
        }
        struct sr_arpreq* arp_request = sr_arpcache_queuereq(&sr->cache, rt_entry->gw.s_addr,
         ip_packet_copy, packet_len, rt_entry->interface);
        handle_arpreq(sr, arp_request);
        free(ip_packet_copy);
    }
    if (arp_item) {
        free(arp_item);
    }

}

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

void sr_handlepacket(struct sr_instance* sr,
                     uint8_t * packet/* lent */,
                     unsigned int len,
                     char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    
    printf("*** -> Received packet of length %d \n",len);
    
    if (len < sizeof(struct sr_ethernet_hdr)) return;
    
    if (ethertype(packet) == ethertype_ip) {
        
        /* print_hdrs(packet, len); */
        
        sr_ip_hdr_t* ip_packet =
        (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

        /* check checksum and length */
        if (len < (sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr)))
            return; 

        uint16_t checksum = ip_packet->ip_sum;
        ip_packet->ip_sum = 0;
        uint16_t expected_checksum = cksum(ip_packet, ip_packet->ip_hl*4);
        if (checksum != expected_checksum) {
            printf("^^^^^^^^^^^^^^^^^^^^^^ DROPPING PACKET \n");
            return;
        }
        /* printf("RECIEVED ETHER TYPE PACKET below******************\n"); */
        /* print_hdrs(packet, len); */
        
        if(is_in_interface_lst(sr, ip_packet->ip_dst)) {
            /* its me, then check if ICMP request */
            printf("            IP PROTOCOL %d\n", ip_protocol(packet + sizeof(struct sr_ethernet_hdr)));
            if (ip_protocol(packet + sizeof(struct sr_ethernet_hdr)) == (uint8_t)ip_protocol_icmp)  {
                /* send echo reply */
                printf(" ***************** MAKINg AN EHCOOOOOOOO\n\n\n\n\n");                
                make_and_send_icmp(sr, ip_packet, 0, 0, interface);
                
            } else {
                /* send icmp port unreachable since its udp/tcp packet */
                make_and_send_icmp(sr, ip_packet, 3, 3, interface);
                print_hdrs(packet, len);

                /* printf(" RECIEVED A TCP/UDP PACKET ************************************** \n\n\n"); */
                
            }
        } else {
            /* its not me, must fwd it*/
           
            
            unsigned int len_packet = ntohs(ip_packet->ip_len);
            ip_packet->ip_ttl--;
            if (ip_packet->ip_ttl == 0) {
                /* send icmp time exceeded */
                make_and_send_icmp(sr, ip_packet, 11, 0, interface);
                return;
            }
            
            ip_packet->ip_sum = 0;
            ip_packet->ip_sum = cksum(ip_packet, ip_packet->ip_hl*4);
            /* printf(" NOT FOR ME, FWDING ******************************** ntohs ip_len %d *4 method %d  \n\n\n", len_packet,  ip_packet->ip_hl*4); */
            uint8_t* ip_packet_copy_to_fwd = malloc(len_packet);
            memcpy(ip_packet_copy_to_fwd, ip_packet, len_packet);
            send_packet(sr, ip_packet_copy_to_fwd, len_packet, ip_packet->ip_dst, ethertype_ip, 1);
            /* ma(sr, (uint8_t*) ip_packet_copy_to_fwd, len); */
            /* free(ip_packet_copy_to_fwd); */
            
        }
    } else {
        /* ARP */

        /* meet minimum length */
        if ((sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) > len)
            return;


        sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (packet + sizeof(struct sr_ethernet_hdr));
        
        uint32_t ip = arp_header->ar_sip;
        struct sr_arpentry *arp_item = sr_arpcache_lookup(&sr->cache, arp_header->ar_sip);

        if (arp_item == NULL) {

            printf(" *** GOT ARP REPLY\n");
            struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, ip);
        
            if (req != NULL) {
                /* send out all packets that were waiting on reply to this arp req*/
                struct sr_packet* sr_pckt = req->packets;
                sr_ip_hdr_t *ip_header;

                while (sr_pckt != NULL) {
                    ip_header = (sr_ip_hdr_t*) sr_pckt->buf;
                    send_packet(sr, sr_pckt->buf, sr_pckt->len, ip_header->ip_dst, ethertype_ip, 1);
                    sr_pckt = sr_pckt->next;
                }
                sr_arpreq_destroy(&sr->cache, req);
            }

        } else {
            free(arp_item);
        }

        if (ntohs(arp_header->ar_op) == arp_op_request) {
            
            /*printf("RECIEVED ARP REQUEST   **********   \n");*/
            
            send_arp_reply(sr, arp_header, interface, packet, len);
            
        }       
    }
    
}
