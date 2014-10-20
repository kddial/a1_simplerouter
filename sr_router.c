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

/*
 * Macros
 */
#define LOG(...) fprintf(stderr, __VA_ARGS__)
#define TTL (100)
 #define ICMP_ECHO_REQUEST (8)
 #define ICMP_ECHO_REPLY (0)

/*
 * Static variables
 */
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

  /* Error handling */
  if (len < sizeof(sr_ethernet_hdr_t))
  {
    LOG("Invalid packet, insufficient length.\n");
    return;
  }
  struct sr_if* iface = sr_get_interface(sr, interface);
  if (iface == 0)
  {
    LOG("Invalid interface, interface not found.\n");
  }

  /* ARP packet */
  if (ethertype(packet) == ethertype_arp)
  {
    if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
    {
      LOG("Invalid ARP packet, insufficient length.\n");
      return;
    }

    /* ARP header */
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    if (arp_hdr->ar_tip == iface->ip)
    {

      /* ARP REQUEST */
      if (ntohs(arp_hdr->ar_op) == arp_op_request) 
      {
        /* Contruct ARP reply */
        LOG("Received ARP request. Reply is being sent.\n");
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
        printf("\n Received ARP reply. ** TO DO **********\n");
        /* Insert into ARP cache */
        /* Send outstanding packets from request */
        /* Destroy request */
      }
    }
  }
  /* IP packet */
  else if (ethertype(packet) == ethertype_ip)
  {
    /* Error handling */
    if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)))
    {
      LOG("Invalid IP packet, insufficient length.\n");
      return;
    }

    /* Authenticate checksum */
    sr_ip_hdr_t* ip_packet = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    uint16_t temp_checksum = ip_packet->ip_sum;
    ip_packet->ip_sum = 0;

    if (temp_checksum != cksum(ip_packet, sizeof(sr_ip_hdr_t))){
      LOG("Invalid IP packet, incorrect checksum.\n");
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
    if (destination_ip_belong_to_us == 1){

      /* Handle ICMP */
      if(ip_packet->ip_p == ip_protocol_icmp){

        /* Error handling */
        if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
          + sizeof(sr_icmp_hdr_t)))
        {
          LOG("Invalid ICMP packet, insufficient length.\n");
          return;
        }

        sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet 
          + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* Authenticate ICMP checksum */
        temp_checksum = icmp_hdr->icmp_sum;
        icmp_hdr->icmp_sum = 0;
        int icmp_length = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
        if (temp_checksum != cksum(icmp_hdr, icmp_length)){
          LOG("Invalid ICMP, incorrect checksum.\n");
          return;
        }
        icmp_hdr->icmp_sum = temp_checksum;

        /* Check if ICMP is an echo request (8) */
        if (icmp_hdr->icmp_type == ICMP_ECHO_REQUEST)
        {
          LOG("Received echo request. Sending reply.\n");

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

          /* Send reply packet */
          sr_send_packet(sr, reply_packet, len, interface);

          free(reply_packet);
        }
        /* Handle unexpected packet */
        else
        {
          LOG("Received unexpected ICMP packet.\n");
        }
      }
      /* Send ICMP type 3, port unreachable */
      else
      {

      }
    }
    /* Forward destination IP packet */
  }
}/* end sr_ForwardPacket */

























































