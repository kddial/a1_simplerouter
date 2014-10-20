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
 * Macro for Error outputs
 */
#define LOG(...) fprintf(stderr, __VA_ARGS__)






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
    return -1;
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
      return -1;
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

        LOG("\n!!REQUEST!!");
        print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));
        LOG("!!REPLY!!");
        print_hdr_arp((uint8_t*)reply_arp_hdr);

        free(reply_arp_packet);
      }

      /* ARP Reply */
      else if (ntohs(arp_hdr->ar_op) == arp_op_reply)
      {
        printf("\n Received ARP reply. ** TO DO **********\n");
        /*sr_arpcache_dump(&sr->cache);*/
        /* Insert into ARP cache */
        /*struct sr_arpreq* arp_request_pointer = sr_arpcache_insert(&sr->cache, iface->addr, iface->ip);*/
        /*      struct sr_arpreq* requestPointer = sr_arpcache_insert(
               &sr->cache, packet->ar_sha, ntohl(packet->ar_sip));*/
        /* Send outstanding packets from request */
        /* Destroy request */
      }
    }
  }
  /* IP packet */
  else if (ethertype(packet) == ethertype_ip)
  {
    LOG("\nIP PACKET! ************* \n");
  }


}/* end sr_ForwardPacket */

























































