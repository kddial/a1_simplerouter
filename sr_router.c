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
#define ICMP_UNREACHABLE (3)
#define ICMP_CODE_DEST_NETWORK_UNREACH (0)
#define ICMP_CODE_DEST_HOST_UNREACH (1)
#define ICMP_CODE_DEST_PORT_UNREACH (3)
static uint16_t id_counter = 0;
static uint8_t ethernet_broadcast_addr[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint8_t blank_addr[ETHER_ADDR_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

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

    /* Received ARP Request */
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

    /* Received ARP Reply */
    else if (ntohs(arp_hdr->ar_op) == arp_op_reply)
    {
      printf("Received ARP reply. \n");

      /* Insert into ARP cache */
      struct sr_arpreq* request_pointer = sr_arpcache_insert(&sr->cache, 
        arp_hdr->ar_sha, ntohl(arp_hdr->ar_sip));

      
      if (request_pointer != NULL)
      {


        /* Send all oustanding packets from request */
        while (request_pointer->packets != NULL)
        {
          /* Set new Ethernet frame destination address */
          struct sr_packet* current_packet = request_pointer->packets;
          memcpy(
            ((sr_ethernet_hdr_t*) current_packet->buf),
            arp_hdr->ar_sha, ETHER_ADDR_LEN);

          sr_send_packet(sr, (uint8_t*)current_packet->buf, current_packet->len, current_packet->iface);

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

      printf("-------------- -----------------10  ------------- \n");
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

  printf("------------------ -----------------0------------ ------------------\n");

  printf("------------------ -----------------dest: %d------------ ------------------\n", destination_ip_belong_to_us);


  /* Received IP packet destined to us */
  if (destination_ip_belong_to_us == 1)
  {
    printf("------------------ destination is us, handling icmp ------------------\n");
    /* Handle ICMP packet */
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
        sr_ip_hdr_t* reply_ip_header = (sr_ip_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t));
        sr_icmp_hdr_t* reply_icmp_header = (sr_icmp_hdr_t*)(reply_packet 
                                          + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

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
        sr_send_ip_packet(sr, 
          (sr_ethernet_hdr_t*) reply_packet, len, interface,
          sr_get_ip_packet_route(sr, ntohl(ip_packet->ip_src))
        );
        free(reply_packet);
      }

    }
    if (ip_packet->ip_p != ip_protocol_icmp)
    {
      /* Handle non-ICMP packet */
      printf("Received non-ICMP packet. Sending port unreachable.\n");

      /* Send ICMP type 3 packet */
      sr_send_icmp_t3_packet(sr, ip_packet, 
        len, interface, ICMP_CODE_DEST_PORT_UNREACH);
    }
  }
  /* Forward IP packet */
  else
  {
    printf("------------------ dest is not us, need to forward IP packet------------\n");





  }
  printf("------------------ IP packet end ------------------\n");
}



void sr_send_ip_packet(struct sr_instance* sr, sr_ethernet_hdr_t* packet,
   unsigned int len, char* interface, struct sr_rt* route)
{
  uint32_t next_hop_ip_addr;
  struct sr_arpentry* arp_entry;

  printf("------------arp cahch lookup-------------\n");
  /* Set ethernet source addr */
  struct sr_if* request_iface = sr_get_interface(sr, interface);
  struct sr_if* route_iface = sr_get_interface(sr, route->interface);
  memcpy(packet->ether_shost, route_iface->addr, ETHER_ADDR_LEN);
  packet->ether_type = ntohs(ethertype_ip);

  /* Find gateway IP for arp cahce lookup */
  next_hop_ip_addr = ntohl(route->gw.s_addr);
  arp_entry = sr_arpcache_lookup(&sr->cache, next_hop_ip_addr);

        printf(" --------$$$$$$$$$$$$$$$$--------- next hop address ----$$$$$$$$$$$$$$----\n");
  print_addr_ip_int(route->gw.s_addr);
  print_addr_ip_int(next_hop_ip_addr);


  if (arp_entry != NULL)
  {
    /* Arp cache found, send packet */
    printf("------------arp cache found-------------\n");
    memcpy(packet->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, (uint8_t*)packet, len, route_iface->name);
    free(arp_entry);
  }
  else
  {
    /* Arp cache not found */
    printf("----------arp cache NOT found---------\n");

    struct sr_arpreq* arp_request_entry = sr_arpcache_queuereq(
      &sr->cache, next_hop_ip_addr, (uint8_t*)packet, len, route->interface);


    if (arp_request_entry->times_sent == -1)
    {


      /* Contruct and send a new ARP request */
      uint8_t* request_arp_packet = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
      sr_ethernet_hdr_t* request_ethernet_hdr = (sr_ethernet_hdr_t*)request_arp_packet;
      sr_arp_hdr_t* request_arp_hdr = (sr_arp_hdr_t*)(request_arp_packet + sizeof(sr_ethernet_hdr_t));

      /* Ethernet header */
      /* Destination addr is set to FF:FF:FF:FF:FF:FF */


      /*memcpy(((sr_ethernet_hdr_t*) packet)->ether_dhost, ethernet_broadcast_addr, ETHER_ADDR_LEN);
 */
      memcpy(request_ethernet_hdr->ether_dhost, ethernet_broadcast_addr, ETHER_ADDR_LEN);
      memcpy(request_ethernet_hdr->ether_shost, request_iface->addr, ETHER_ADDR_LEN);
      request_ethernet_hdr->ether_type = htons(ethertype_arp);

      /* ARP Header */
      request_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
      request_arp_hdr->ar_pro = htons(ethertype_ip);
      request_arp_hdr->ar_hln = ETHER_ADDR_LEN;
      request_arp_hdr->ar_pln = IP_ADDR_LEN;
      request_arp_hdr->ar_op = htons(arp_op_request);
      memcpy(request_arp_hdr->ar_sha, route_iface->addr, ETHER_ADDR_LEN);
      request_arp_hdr->ar_sip = route_iface->ip;

      /* Target addr set to 00:00:00:00:00:00 */
      memcpy(request_arp_hdr->ar_tha, blank_addr, ETHER_ADDR_LEN);
      request_arp_hdr->ar_tip = htonl(arp_request_entry->ip);





      print_hdrs(request_arp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
/*    
      printf("------------printing all headers, from eth packet request--------\n");
      print_hdrs(eth_packet, len);

      
      printf("------------printing all headers, from arp packet request--------\n");
      print_hdrs(request_arp_packet, len);
      */

      printf("Sending ARP request to %u.%u.%u.%u on %s\n", 
        (arp_request_entry->ip >> 24) & 0xFF,
        (arp_request_entry->ip >> 16) & 0xFF,
        (arp_request_entry->ip >> 8) & 0xFF,
        arp_request_entry->ip & 0xFF,
        route_iface->name);

      printf("---------------- begin SENDING, interface name: %s ------------\n", route_iface->name);
      sr_send_packet(sr, request_arp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), route_iface->name);
      free(request_arp_packet);

      printf("---------------- DONE SENDING------------\n");


      arp_request_entry->times_sent = 1;
      arp_request_entry->sent = time(NULL);
    }
  }
}







struct sr_rt* sr_get_ip_packet_route(struct sr_instance* sr, uint32_t dest_addr)
{
  struct sr_rt* route_walker = sr->routing_table;
  struct sr_rt* ret = NULL;
  int network_mask_length = -1;

  while (route_walker != NULL)
  {
        printf("---------- while loop of route walker ------------\n");
        print_addr_ip_int(dest_addr);
        print_addr_ip_int(route_walker->dest.s_addr);

    /* Find longest prefix match */
    if (get_mask_length(route_walker->mask.s_addr) > network_mask_length)
    {
      /* Check if destination matches */
      if ((dest_addr & route_walker->mask.s_addr) 
        == ((ntohl(route_walker->dest.s_addr)) & route_walker->mask.s_addr))
      {
        printf("---------- longest prefix match found ------------\n");
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
int get_mask_length(uint32_t mask)
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



void sr_send_icmp_t3_packet(struct sr_instance* sr, sr_ip_hdr_t* ip_packet,
   unsigned int len, char* interface, int icmp_code)
{
  /* Construct reply packet */
  uint8_t* reply_packet = malloc(sizeof(sr_ethernet_hdr_t) 
    + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

  sr_ip_hdr_t* reply_ip_header = (sr_ip_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* reply_icmp_header = (sr_icmp_t3_hdr_t*)(reply_packet 
                                    + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

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
  reply_ip_header->ip_dst = ip_packet->ip_src;

  /* Find IP destination interface */


    print_hdr_ip(ip_packet);
      printf("---------------- ip split ------------\n");
    print_hdr_ip(reply_ip_header);

  struct sr_rt* dest_route = sr_get_ip_packet_route(sr, ntohl(reply_ip_header->ip_dst));
  printf("--------------dest_rout: %s===------------\n", dest_route);

      printf("---------------- t3  10  ------------\n");
      print_addr_ip_int(ip_packet->ip_dst);
      print_addr_ip_int(ntohl(ip_packet->ip_dst));
      printf("---------------- t3  101, interface name: %s  ------------\n", dest_route->interface);

  struct sr_if* dest_if = sr_get_interface(sr, dest_route->interface);
      printf("---------------- t3  11  ------------\n");
  reply_ip_header->ip_src = dest_if->ip;
      printf("---------------- t3  12  ------------\n");
  reply_ip_header->ip_sum = cksum(reply_ip_header, sizeof(sr_ip_hdr_t));

      printf("---------------- t3  13  ------------\n");
  /* ICMP header */
  reply_icmp_header->icmp_type = ICMP_UNREACHABLE;
  reply_icmp_header->icmp_code = icmp_code;
  reply_icmp_header->icmp_sum = 0;
  memcpy(reply_icmp_header->data, ip_packet, ICMP_DATA_SIZE);
  reply_icmp_header->icmp_sum = cksum(reply_icmp_header, sizeof(sr_icmp_t3_hdr_t));

      printf("---------------- t3  2  ------------\n");
  /* Send reply packet */
  sr_send_ip_packet(sr, 
    (sr_ethernet_hdr_t*) reply_packet, 
    sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t),
    interface,
    sr_get_ip_packet_route(sr, ntohl(reply_ip_header->ip_dst))
  );
      printf("---------------- t3  3  ------------\n");
  free(reply_packet);
      printf("---------------- t3  4  ------------\n");
}













