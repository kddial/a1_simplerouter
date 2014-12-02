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
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/**********
 * Macros, static variables, privte functions
 ***********/
#define TTL (100)
#define ICMP_ECHO_REQUEST (8)
#define ICMP_ECHO_REPLY (0)
static uint16_t id_counter = 0;

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

  /* fill in code here */
  printf("------------------ handle packet begin ------------------\n");
  print_hdrs(packet, len);

  /* Error handling */
  if (len < sizeof(sr_ethernet_hdr_t))
  {
    printf("Invalid packet, insufficient length.\n");
    return;
  }

  struct sr_if* iface = sr_get_interface(sr, interface);
  
  if (iface == 0)
  {
    printf("Invalid interface, interface not found.\n");
  }

  /* Handle ARP packet */
  if (ethertype(packet) == ethertype_arp)
  {
    printf("------------------ ARP packet begin ------------------\n");
    sr_handle_arp_packet(sr, packet, len, interface, iface);
  }
  /* Handle IP packet */
  else if (ethertype(packet) == ethertype_ip)
  {
    printf("------------------ IP packet begin ------------------\n");
    sr_handle_ip_packet(sr, packet, len, interface, iface);
  }


}/* end sr_ForwardPacket */





void sr_handle_arp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */,
        struct sr_if* iface)
{
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
  {
    printf("Invalid ARP packet, insufficient length.\n");
    return;
  }

  /* ARP header */
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  
  if (arp_hdr->ar_tip == iface->ip)
  {

    /* ARP Request */
    if (ntohs(arp_hdr->ar_op) == arp_op_request) 
    {
      /* Contruct ARP reply */
      printf("Received ARP request. Reply is being sent.\n");

      uint8_t* reply_arp_packet = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
      sr_ethernet_hdr_t* reply_ethernet_hdr = (sr_ethernet_hdr_t*)reply_arp_packet;
      sr_arp_hdr_t* reply_arp_hdr = (sr_arp_hdr_t*)(reply_arp_packet + sizeof(sr_ethernet_hdr_t));

      /* Ethernet header */
      memcpy(reply_ethernet_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(reply_ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
      reply_ethernet_hdr->ether_type = htons(ethertype_arp);

      /* ARP Header */
      reply_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
      reply_arp_hdr->ar_pro = htons(ethertype_ip);
      reply_arp_hdr->ar_hln = ETHER_ADDR_LEN;
      reply_arp_hdr->ar_pln = IP_ADDR_LEN;
      reply_arp_hdr->ar_op = htons(arp_op_reply);
      memcpy(reply_arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
      reply_arp_hdr->ar_sip = iface->ip;
      memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      reply_arp_hdr->ar_tip = arp_hdr->ar_sip;

      /* Send reply packet */
      sr_send_packet(sr, (uint8_t*)reply_arp_packet, (sizeof(sr_ethernet_hdr_t) 
        + sizeof(sr_arp_hdr_t)), interface);

      free(reply_arp_packet);
    }

    /* ARP Reply */
    else if (ntohs(arp_hdr->ar_op) == arp_op_reply)
    {
      printf("Received ARP reply. \n");
      printf("-------------- needs testing.------------- \n");

      /* Insert into ARP cache */
      struct sr_arpreq* request_pointer = sr_arpcache_insert(&sr->cache, 
        arp_hdr->ar_sha, arp_hdr->ar_sip);

      if (request_pointer != NULL)
      {

        /* Send all oustanding packets from request */
        while (request_pointer != NULL)
        {
          /* Set new Ethernet frame destination address */
          struct sr_packet* current_packet = request_pointer->packets;
          memcpy(
            ((sr_ethernet_hdr_t*) current_packet->buf),
            arp_hdr->ar_sha, ETHER_ADDR_LEN);

          sr_send_packet(sr, current_packet->buf, current_packet->len, current_packet->iface);

           /* Iterate to the next packet */
          request_pointer->packets = request_pointer->packets->next;

          /* Free sent packets */
          free(current_packet->buf);
          free(current_packet->iface);
          free(current_packet);
        }

        sr_arpreq_destroy(&sr->cache, request_pointer);
      }
      else
      {
        printf("Received ARP reply, missing associated ARP request.");
      }
    }
  }
}


void sr_handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */,
        struct sr_if* iface)
{
  /* Error handling */
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)))
  {
    printf("Invalid IP packet, insufficient length.\n");
    return;
  }

  /* Authenticate checksum */
  sr_ip_hdr_t* ip_packet = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  uint16_t temp_checksum = ip_packet->ip_sum;
  ip_packet->ip_sum = 0;

  if (temp_checksum != cksum(ip_packet, sizeof(sr_ip_hdr_t)))
  {
    printf("Invalid IP packet, incorrect checksum.\n");
    return;
  }
  ip_packet->ip_sum = temp_checksum;

  /* Check if the destination IP belongs to any of our interfaces */
  int destination_ip_belong_to_us = 0;
  struct sr_if* if_walker = 0;
  if(sr->if_list != 0)
  {
    if_walker = sr->if_list;

    while(if_walker)
    {
      if (if_walker->ip == ip_packet->ip_dst)
      {
        destination_ip_belong_to_us = 1;
      }
      if_walker = if_walker->next;
    }
  }

  /* Handle destination IP packet */
  if (destination_ip_belong_to_us == 1)
  {
    printf("------------------ destination is us, handling icmp ------------------\n");
    /* Handle ICMP */
    if(ip_packet->ip_p == ip_protocol_icmp)
    {
      /* Error handling */
      if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
        + sizeof(sr_icmp_hdr_t)))
      {
        printf("Invalid ICMP packet, insufficient length.\n");
        return;
      }

      sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet 
        + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      /* Authenticate ICMP checksum */
      temp_checksum = icmp_hdr->icmp_sum;
      icmp_hdr->icmp_sum = 0;
      int icmp_length = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
      if (temp_checksum != cksum(icmp_hdr, icmp_length))
      {
        printf("Invalid ICMP, incorrect checksum.\n");
        return;
      }
      icmp_hdr->icmp_sum = temp_checksum;

      /* Check if ICMP is an echo request (8) */
      if (icmp_hdr->icmp_type == ICMP_ECHO_REQUEST)
      {
        printf("Received echo request. Sending reply.\n");

        /* Construct reply packet */
        uint8_t* reply_packet = malloc(len);
        sr_ethernet_hdr_t* reply_eth_header = (sr_ethernet_hdr_t*)reply_packet;
        sr_ip_hdr_t* reply_ip_header = (sr_ip_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t));
        sr_icmp_hdr_t* reply_icmp_header = (sr_icmp_hdr_t*)(reply_packet 
                                          + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* Ethernet header */
        memcpy(reply_eth_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
        reply_eth_header->ether_type = ntohs(ethertype_ip);

        /* IP header */
        reply_ip_header->ip_v = ip_packet->ip_v;
        reply_ip_header->ip_hl = ip_packet->ip_hl;
        reply_ip_header->ip_tos = ip_packet->ip_tos;
        reply_ip_header->ip_len = ip_packet->ip_len;
        reply_ip_header->ip_id = htons(id_counter);
        id_counter++;
        reply_ip_header->ip_off = ip_packet->ip_off;
        reply_ip_header->ip_ttl = TTL;
        reply_ip_header->ip_p = ip_protocol_icmp;
        reply_ip_header->ip_sum = 0;
        reply_ip_header->ip_src = ip_packet->ip_dst;
        reply_ip_header->ip_dst = ip_packet->ip_src;
        reply_ip_header->ip_sum = cksum(reply_ip_header, sizeof(sr_ip_hdr_t));

        /* ICMP header */
        memcpy(reply_icmp_header, icmp_hdr, icmp_length);
        reply_icmp_header->icmp_type = ICMP_ECHO_REPLY;
        reply_icmp_header->icmp_code = 0;
        reply_icmp_header->icmp_sum = 0;
        reply_icmp_header->icmp_sum = cksum(reply_icmp_header, icmp_length);

        printf("---------------icmp echo reply packet -------------- \n");
        print_hdrs(reply_packet, len);

        /* remvove print later */
        sr_print_routing_table(sr);


        /* Send reply packet */
        sr_send_packet_link_arp(sr, 
          reply_packet, len, interface, 
          sr_get_ip_packet_route(sr, ntohl(ip_packet->ip_src))
        );
        free(reply_packet);
      }

    }
  }


  printf("------------------ IP packet end ------------------\n");
}



struct sr_rt* sr_get_ip_packet_route(struct sr_instance* sr, uint32_t dest_addr)
{
  struct sr_rt* route_walker = sr->routing_table;
  struct sr_rt* ret = NULL;
  int network_mask_length = -1;

  while (route_walker != NULL)
  {
    /* Find longest prefix match */
    if (get_mask_length(route_walker->mask.s_addr) > network_mask_length)
    {
      /* Check if destination matches */
      if ((dest_addr & route_walker->mask.s_addr) 
        == ((ntohl(route_walker->dest.s_addr)) & route_walker->mask.s_addr))
      {
        printf("---------- longest prefix match found ------------\n");
        sr_print_routing_entry(route_walker);
        ret = route_walker;
        network_mask_length = get_mask_length(route_walker->mask.s_addr);
      }
    }
    route_walker = route_walker->next;
  }
  return ret;
}

/**
 * Get the mask length
 */
static int get_mask_length(uint32_t mask)
{
   int ret = 0;
   uint32_t bit_iterator = 0x80000000;
   
   while ((bit_iterator != 0) && ((bit_iterator & mask) != 0))
   {
      bit_iterator >>= 1;
      ret++;
   }
   
   return ret;
}

void sr_send_packet_link_arp(struct sr_instance* sr, sr_ethernet_hdr_t* packet,
   unsigned int len, char* interface, struct sr_rt* route)
{
  uint32_t next_hop_ip_addr;
  struct sr_arpentry* arp_entry;

  printf("--------------arp dump-------------\n");
  sr_arpcache_dump(&sr->cache);


  printf("------------arp cahch lookup-------------\n");
  /* Find gateway IP for arp cahce lookup */
  next_hop_ip_addr = ntohl(route->gw.s_addr);
  arp_entry = sr_arpcache_lookup(&sr->cache, next_hop_ip_addr);

  if (arp_entry != NULL)
  {
    /* Arp cache found, send packet */
    printf("------------arp cache found-------------\n");
    memcpy(packet->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, interface);
    free(arp_entry);
  }
  else
  {
    /* Arp cache not found, create an ARP request */
    printf("----------arp cache NOT found---------\n");

    struct sr_arpreq* arp_request_ptr = sr_arpcache_queuereq(
      &sr->cache, next_hop_ip_addr, packet, len, interface);

    if (arp_request_ptr->times_sent == -1)
    {
      /* New ARP request */


      arp_request_ptr->times_sent = 1;
      arp_request_ptr->sent = time(NULL);
    }
  }

}

















