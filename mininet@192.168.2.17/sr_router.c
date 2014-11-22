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
    
    printf("SENDING ARP REPLY     ****************************** \n");
    
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
    
    print_hdrs(packet, len);
    sr_send_packet(sr, packet, len, interface);
    
    free(arp_reply_header);
    
}

void send_packet(struct sr_instance* sr, struct sr_packet* sr_pckt,
                 unsigned char mac[ETHER_ADDR_LEN], uint32_t ip) {
    
    uint8_t *buf = sr_pckt->buf;
    
    struct sr_if* iface = sr_get_interface(sr, sr_pckt->iface);
    
    sr_ethernet_hdr_t* ether_frame = (sr_ethernet_hdr_t*)buf;
    
    memcpy(ether_frame->ether_dhost, mac, ETHER_ADDR_LEN);
    memcpy(ether_frame->ether_shost, iface->addr, ETHER_ADDR_LEN);
    
    print_hdrs(buf, sr_pckt->len);
    
    sr_send_packet(sr, buf, sr_pckt->len, sr_pckt->iface);
    
}


struct sr_rt* longest_prefix_match(struct sr_instance* sr, uint32_t ip_dst){
    struct sr_rt* cur = sr->routing_table;
    struct sr_rt* longest = NULL;
    unsigned long match_len = 0;
    
    while(cur != NULL) {
        if (((cur->dest.s_addr & cur->mask.s_addr) ==
             (ip_dst & cur->mask.s_addr)) & (match_len <= cur->mask.s_addr)){
            
            match_len = cur->mask.s_addr;
            longest = cur;
            
        }
        cur = cur->next;
    }
    return longest;
}

void send_icmp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, uint8_t dest) {
    
    sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*) malloc(sizeof(sr_ethernet_hdr_t));
    struct sr_rt* rt = longest_prefix_match(sr, dest);
    
    if (rt == NULL) {
        return;
    }
    
    struct sr_if* iface = sr_get_interface(sr, rt->interface);
    struct sr_arpentry* arp_item = sr_arpcache_lookup(&(sr->cache),
                                                      rt->dest.s_addr);
    
    if (arp_item == NULL) {
        uint8_t* packet_copy = malloc(len);
        memcpy(packet_copy, packet, len);

        struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), rt->dest.s_addr,
                                                     packet_copy, len, iface->name);
        handle_arpreq(sr, req);
        free(packet_copy);
    } else {
        ether_header->ether_type = htons(ethertype_ip);
        memcpy(ether_header->ether_dhost, &arp_item->mac, ETHER_ADDR_LEN);
        memcpy(ether_header->ether_shost, iface->addr, ETHER_ADDR_LEN);

        uint8_t *ether_packet = malloc(len + sizeof(sr_ethernet_hdr_t));
        memcpy(ether_packet, ether_header, sizeof(sr_ethernet_hdr_t));
        memcpy(ether_packet + sizeof(sr_ethernet_hdr_t), packet, len);

        /* print_hdrs(packet, len); */
        
        sr_send_packet(sr, ether_packet, len + sizeof(sr_ethernet_hdr_t), iface->name);
    }
    
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


void forward_packet(struct sr_instance* sr, uint8_t* buf, unsigned int len) {
    
    sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*)buf;
    sr_ip_hdr_t* ip_packet =
    (struct sr_ip_hdr *)(buf + sizeof(struct sr_ethernet_hdr));
    
    if (is_in_interface_lst(sr, ip_packet->ip_dst)==0) {
        /* hit an interface, just echo */
        
        uint16_t len_packet = ntohs(ip_packet->ip_len);
        uint32_t dest = ip_packet->ip_src;
        ip_packet->ip_src = ip_packet->ip_dst;
        ip_packet->ip_dst = dest;
        
        sr_icmp_hdr_t* icmp_header =
        (sr_icmp_hdr_t*)(buf + 4*ip_packet->ip_hl);
        icmp_header->icmp_sum = 0;
        icmp_header->icmp_code = 0;
        icmp_header->icmp_type = 0;
        
        uint8_t* new_packet = (uint8_t*)malloc(len_packet);
        memcpy(new_packet, ip_packet, len_packet);
        memcpy(new_packet + 4*ip_packet->ip_hl, icmp_header,
               sizeof(struct sr_icmp_hdr));
        sr_icmp_hdr_t* new_icmp =
        (sr_icmp_hdr_t*)(new_packet + 4*ip_packet->ip_hl);
        new_icmp->icmp_sum = cksum(new_icmp, len_packet - 4*ip_packet->ip_hl);
        
        send_icmp_packet(sr, new_packet, len_packet, dest);
    }
    
    struct sr_rt* rt = longest_prefix_match(sr, ip_packet->ip_dst);
    
    if (rt == NULL) {
        /* send icmp host unreachable */
        return;
    }
    
    struct sr_if* iface = sr_get_interface(sr, rt->interface);
    struct sr_arpentry* arp_item = sr_arpcache_lookup(&(sr->cache),
                                                      rt->gw.s_addr);
    
    if (arp_item == NULL) {
        uint8_t* buf_cpy = malloc(len);
        memcpy(buf_cpy, buf, len);
        struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), rt->gw.s_addr,
                                                     buf_cpy, len, iface->name);
        handle_arpreq(sr, req);
    } else {
        memcpy(ether_header->ether_dhost, &arp_item->mac, ETHER_ADDR_LEN);
        memcpy(ether_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
        
        print_hdrs(buf, len);
        
        sr_send_packet(sr, buf, len, iface->name);
    }
}

/* new helper functions */

void make_and_send_icmp(struct sr_instance* sr, sr_ip_hdr_t* ip_packet,
int icmp_type, int icmp_code) {

    if (icmp_type == 3) {
        struct sr_icmp_t3_hdr* icmp_header = 
        (struct sr_icmp_t3_hdr*) malloc(sizeof(struct sr_icmp_t3_hdr)); 

        struct sr_ip_hdr* ip_header = 
        (struct sr_ip_hdr*) malloc(sizeof(struct sr_ip_hdr));

        icmp_header->icmp_type = icmp_type;
        icmp_header->icmp_code = icmp_code;

        icmp_header->unused = 0;
        memcpy(icmp_header->data, ip_packet, ICMP_DATA_SIZE);
        icmp_header->icmp_sum = cksum(icmp_header, sizeof(struct sr_icmp_t3_hdr));
        ip_header->ip_dst = ip_packet->ip_src;
        ip_header->ip_id = ip_packet->ip_id;
        ip_header->ip_p = ip_protocol_icmp;
        ip_header->ip_hl = 5;
        ip_header->ip_tos = 0;
        ip_header->ip_off = htons(IP_DF);
        ip_header->ip_ttl = 100;

        struct sr_rt* rt_entry = longest_prefix_match(sr, ip_header->ip_dst);
        if (rt_entry == NULL) {
            /* ignore */
            return;
        }

        struct sr_if *inf = sr_get_interface(sr, (const char*)rt_entry->interface);

        ip_header->ip_src = inf->ip;

        ip_header->ip_len = htons(ip_header->ip_hl*4 + sizeof(struct sr_icmp_t3_hdr));
        ip_header->ip_sum = cksum(ip_header, ip_header->ip_hl*4);

        unsigned int len = 4*ip_header->ip_hl + sizeof(struct sr_icmp_t3_hdr);
        uint8_t* packet = malloc(len);

        memcpy(packet, ip_header, 4*ip_header->ip_hl);
        memcpy(packet + 4*ip_header->ip_hl, icmp_header,
         sizeof(struct sr_icmp_t3_hdr));

        send_icmp_packet(sr, packet, len, ip_header->ip_dst);


    } else {
       /* struct sr_icmp_hdr* icmp_header = 
        (struct sr_icmp_hdr*) malloc(sizeof(struct sr_icmp_hdr));*/
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
        if (len != (sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr)))
            return; 

        uint16_t checksum = ip_packet->ip_sum;
        uint16_t expected_checksum = cksum(ip_packet, ip_packet->ip_hl*4);
        if (checksum != expected_checksum)
            return;


        
        if(is_in_interface_lst(sr, ip_packet->ip_dst)) {
            /* its me, then check if ICMP request */
            if (ip_protocol(packet) == ip_protocol_icmp)  {
                /* send echo reply */
                printf(" BING BING BING ************************************** \n\n\n");
                
                uint16_t len_packet = ntohs(ip_packet->ip_len);
                uint32_t dest = ip_packet->ip_src;
                ip_packet->ip_src = ip_packet->ip_dst;
                ip_packet->ip_dst = dest;
                
                sr_icmp_hdr_t* icmp_header =
                (sr_icmp_hdr_t*)(packet + 4*ip_packet->ip_hl);
                icmp_header->icmp_sum = 0;
                icmp_header->icmp_code = 0;
                icmp_header->icmp_type = 0;
                
                uint8_t* new_packet = (uint8_t*)malloc(len_packet);
                memcpy(new_packet, ip_packet, len_packet);
                memcpy(new_packet + 4*ip_packet->ip_hl, icmp_header,
                       sizeof(struct sr_icmp_hdr));
                sr_icmp_hdr_t* new_icmp =
                (sr_icmp_hdr_t*)(new_packet + 4*ip_packet->ip_hl);
                new_icmp->icmp_sum = cksum(new_icmp, len_packet - 4*ip_packet->ip_hl);
                
                send_icmp_packet(sr, new_packet, len_packet, dest);
                
            } else {
                /* send icmp port unreachable */
                
                make_and_send_icmp(sr, ip_packet, 3, 3);

                /*
                uint16_t len_packet = ntohs(ip_packet->ip_len);
                uint32_t dest = ip_packet->ip_src;
                ip_packet->ip_src = ip_packet->ip_dst;
                ip_packet->ip_dst = dest;
                
                sr_icmp_t3_hdr_t* icmp_header =
                (sr_icmp_t3_hdr_t*)(packet + 4*ip_packet->ip_hl);
                icmp_header->icmp_sum = 0;
                icmp_header->icmp_code = 3;
                icmp_header->icmp_type = 3;
                
                uint8_t* new_packet = (uint8_t*)malloc(len_packet);
                memcpy(new_packet, ip_packet, len_packet);
                memcpy(new_packet + 4*ip_packet->ip_hl, icmp_header,
                       sizeof(struct sr_icmp_t3_hdr));
                sr_icmp_t3_hdr_t* new_icmp =
                (sr_icmp_t3_hdr_t*)(new_packet + 4*ip_packet->ip_hl);
                new_icmp->icmp_sum = cksum(new_icmp, len_packet - 4*ip_packet->ip_hl);
                
                send_icmp_packet(sr, packet, new_packet, len_packet, dest);
                */
                printf(" TCP TCP UDP? ************************************** \n\n\n");
                
            }
        } else {
            /* its not me */
            printf(" NOT FOR ME, FWDING ******************************** \n\n\n");
            
            unsigned int len_packet = sizeof(struct sr_ip_hdr);
            ip_packet->ip_ttl--;
            if (ip_packet->ip_ttl == 0) {
                /* send icmp time exceeded */
                return;
            }
            
            ip_packet->ip_sum = 0;
            ip_packet->ip_sum = cksum(ip_packet, ip_packet->ip_hl*4);
            
            sr_ip_hdr_t* ip_packet_copy_to_fwd = (sr_ip_hdr_t*)
            malloc(sizeof(struct sr_ip_hdr));
            memcpy(ip_packet_copy_to_fwd, ip_packet, len_packet);
            forward_packet(sr, packet, len);
            
            
        }
    } else {
        /* ARP */
        sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (packet + sizeof(struct sr_ethernet_hdr));
        
        if (ntohs(arp_header->ar_op) == arp_op_request) {
            
            printf("RECIEVED ARP REQUEST      \n");
            
            send_arp_reply(sr, arp_header, interface, packet, len);
            
        } else {
            printf("RECIEVED ARP REPLY      \n");
            print_hdr_arp((uint8_t*)arp_header);
            uint32_t ip = arp_header->ar_sip;
            struct sr_arpcache cache = sr->cache;
            
            struct sr_arpreq* req = sr_arpcache_insert(&cache, arp_header->ar_sha, ip);
            
            if (req != NULL) {
                /* send out all packets that were waiting on reply to this arp req*/
                struct sr_packet* sr_pckt = req->packets;
                
                while (sr_pckt != NULL) {
                    send_packet(sr, sr_pckt, arp_header->ar_sha, ip);
                    sr_pckt = sr_pckt->next;
                }
                sr_arpreq_destroy(&sr->cache, req);
            }
            
        }
        
    }
    
}
