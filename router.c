#include <arpa/inet.h>
#include <string.h>
#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include "router.h"

// Routing table
struct route_table_entry rt_table[100005];
int rt_table_len;

// ARP table 
struct arp_table_entry arp_table[100005];
int arp_table_len;

// Queue for saved IPv4 packets  
queue arp_pending_queue;


int is_router_interface(uint32_t dest_addr) {

	for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
		// ip_addr_intf will be in Netowk Order
		uint32_t ip_addr_intf; 

		inet_pton(AF_INET, get_interface_ip(i), &ip_addr_intf);
		if (ip_addr_intf == dest_addr) return 1;

	}
	return 0; 
}

int compare_rtable(const void* route1, const void* route2) {
	struct route_table_entry* entry_a = (struct route_table_entry *) route1;
	struct route_table_entry* entry_b = (struct route_table_entry *) route2;

	if (ntohl(entry_a->prefix) != ntohl(entry_b->prefix)) {
		return ntohl(entry_a->prefix) < ntohl(entry_b->prefix) ? -1 : 1;
	}
	
	return ntohl(entry_a->mask) < ntohl(entry_b->mask) ? -1 : 1;
	return 0;
}

void send_icmp_reply(char* buf, size_t len, size_t interface, uint8_t type, uint8_t code, int own_destination) {
	struct ether_hdr* eth_hdr = (struct ether_hdr *) buf;
	struct ip_hdr* iphdr = (struct ip_hdr *) (buf + sizeof(struct ether_hdr));
	struct icmp_hdr* icmphdr = (struct icmp_hdr *) (buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr)); 
	// We can use the icmp header even though it's not an icmp packet. 
	// We make a copy of the original packet in original_ip_and_payload 

	uint8_t aux_mac[6];  
	uint32_t aux_ip_addr = iphdr->source_addr;
	char original_ip_and_payload[sizeof(struct ip_hdr) + 8];

    memcpy(original_ip_and_payload, iphdr, sizeof(struct ip_hdr) + 8);
	memcpy(aux_mac, eth_hdr->ethr_dhost, 6);
	memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
	memcpy(eth_hdr->ethr_shost, aux_mac, 6);
	if (own_destination) {
	iphdr->source_addr = iphdr->dest_addr;
	iphdr->dest_addr = aux_ip_addr;
	} else if (type == ICMP_DESTINATION_UNREACHABLE_TYPE || type == ICMP_TIME_EXCEEDED_TYPE) {
		uint32_t ip_addr_intf; 
		inet_pton(AF_INET, get_interface_ip(interface), &ip_addr_intf);
		iphdr->dest_addr = iphdr->source_addr;
		iphdr->source_addr = ip_addr_intf;
	}
	iphdr->proto = 1;
	iphdr->ttl = 64;

	icmphdr->mtype = type;
	icmphdr->mcode = code;
	if (type == ICMP_TIME_EXCEEDED_TYPE || type == ICMP_DESTINATION_UNREACHABLE_TYPE) {
        memset((char*)icmphdr + 4, 0, 4); 
        memcpy((char*)icmphdr + 8, original_ip_and_payload, sizeof(struct ip_hdr) + 8);
        iphdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);        
        len = sizeof(struct ether_hdr) + ntohs(iphdr->tot_len);
    }
	iphdr->checksum = 0;
	iphdr->checksum = htons(checksum((uint16_t*) iphdr, sizeof(struct ip_hdr)));
	icmphdr->check = 0;
	icmphdr->check = htons(checksum((uint16_t *) icmphdr, ntohs(iphdr->tot_len) - sizeof(struct ip_hdr)));
	send_to_link(len, buf, interface);
}

void send_arp_request(uint32_t ip_dest_addr, size_t interface) {
	const size_t len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr); 
	char buf[len];
	struct ether_hdr* eth_hdr = (struct ether_hdr *) buf;
	struct arp_hdr* arphdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
	uint8_t mac[6];

	memset(buf, 0, len);
	get_interface_mac(interface, mac);
	eth_hdr->ethr_type = htons(ARP);
	memcpy(eth_hdr->ethr_shost, mac, 6);
	memset(eth_hdr->ethr_dhost, 0xFF, 6);
	arphdr->hw_len = 6;
	arphdr->hw_type = htons(1);
	arphdr->opcode = htons(1);
	arphdr->proto_len = 4;
	arphdr->proto_type = htons(0x0800);
	memcpy(arphdr->shwa, mac, 6);
	inet_pton(AF_INET, get_interface_ip(interface), &(arphdr->sprotoa));
	memset(arphdr->thwa, 0, 6);
	arphdr->tprotoa = ip_dest_addr;
	send_to_link(len, buf, interface);
}

void send_arp_reply(char* buf, size_t len, size_t interface) {
	struct ether_hdr* eth_hdr = (struct ether_hdr *) buf;
	struct arp_hdr* arphdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
	uint8_t thwa[6];
	uint32_t aux_ip = arphdr->tprotoa;
	
	get_interface_mac(interface, thwa);
	memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
	memcpy(eth_hdr->ethr_shost, thwa, 6);
	memcpy(arphdr->thwa, arphdr->shwa, 6);
	memcpy(arphdr->shwa, thwa, 6);
	arphdr->tprotoa = arphdr->sprotoa;
	arphdr->sprotoa = aux_ip;
	arphdr->opcode = htons(2);
	send_to_link(len, buf, interface);
}

struct arp_table_entry* get_arp_entry(uint32_t dest_ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == dest_ip) return &arp_table[i];
	}
	return NULL;
}

struct route_table_entry* get_best_route(uint32_t dest_ip, struct route_table_entry* rt_table, int rt_table_len) {
	int left = 0, right = rt_table_len - 1;
	struct route_table_entry* best_route = NULL;

	while (left <= right) {
		int mid = left + (right - left) / 2;
		uint32_t current_prefix = dest_ip & rt_table[mid].mask;
		
		if (current_prefix == rt_table[mid].prefix) {
			best_route = &rt_table[mid];
			left = mid + 1;
		} else if (ntohl(dest_ip) > ntohl(rt_table[mid].prefix)) {
			left = mid + 1;
		} else {
			right = mid - 1;
		}

	}
	return best_route;
}

void forward_ipv4_packet(char* buf, size_t len, size_t interface) {
	struct ether_hdr* eth_hdr = (struct ether_hdr *) buf;
	struct ip_hdr* iphdr = (struct ip_hdr *) (buf + sizeof(struct ether_hdr));
	struct route_table_entry* best_route = get_best_route(iphdr->dest_addr, rt_table, rt_table_len);
	
	if (!best_route) {
		printf("[ROUTER] Cannot forward IPv4 packet. Destination unreachable\n");
		send_icmp_reply(buf, len, interface, ICMP_DESTINATION_UNREACHABLE_TYPE, ICMP_DESTINATION_UNREACHABLE_CODE, 0);
		return;
	}
	
	// struct arp_table_entry* entry_next_hop = send_arp_request(best_route->next_hop, interface);
	// if (!entry_next_hop) {
	// 	printf("[ROUTER] Cannot forward IPv4 packet. Destination unreachable\n");
	// 	send_icmp_reply(buf, len, interface, ICMP_DESTINATION_UNREACHABLE_TYPE, ICMP_DESTINATION_UNREACHABLE_CODE, 0);
	// 	return;
	// }

	// Verify if next_hop is in ARP cache 
	struct arp_table_entry* best_hop_arp_entry = get_arp_entry(best_route->next_hop); 
	if (best_hop_arp_entry) {
	// Modify IPv4 packet and forward
	get_interface_mac(best_route->interface, eth_hdr->ethr_shost);
	memcpy(eth_hdr->ethr_dhost, best_hop_arp_entry->mac, 6);
	iphdr->ttl -= 1;
	iphdr->checksum = 0;
	iphdr->checksum = htons(checksum((uint16_t *)iphdr, sizeof(struct ip_hdr)));
	send_to_link(len, buf, best_route->interface);
	} else {
		printf("[ROUTER] ARP entry not in cache. Sending ARP request\n");
		// TODO: Save packet in queue and send arp request : DONE  
		struct waiting_packet* saved_packet = malloc(sizeof(struct waiting_packet));  
		char* aux_buf = malloc(len);

		memcpy(aux_buf, buf, len);
		saved_packet->buf = aux_buf;
		saved_packet->len = len;
		saved_packet->interface = interface;
		saved_packet->next_hop = best_route->next_hop;
		queue_enq(arp_pending_queue, (void *) saved_packet);
		send_arp_request(best_route->next_hop, best_route->interface);
	}

}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	rt_table_len = read_rtable(argv[1], rt_table);
	arp_pending_queue = create_queue();
	// arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	// LPM uses binary search. Sort is necessary
	qsort(rt_table, rt_table_len, sizeof(struct route_table_entry), compare_rtable); 
	
	// debugging 
	// for (int i = 0; i < rt_table_len; i++) {

    //     struct in_addr prefix_addr, next_hop_addr, mask_addr;

    // 	prefix_addr.s_addr = rt_table[i].prefix;
    // 	next_hop_addr.s_addr = rt_table[i].next_hop;
    // 	mask_addr.s_addr = rt_table[i].mask;

    // 	printf("Prefix: %s | ", inet_ntoa(prefix_addr));
    // 	printf("Next hop: %s | ", inet_ntoa(next_hop_addr));
    // 	printf("Mask: %s | ", inet_ntoa(mask_addr));
    // 	printf("Interface: %d\n", rt_table[i].interface);
	// }


	// Do not modify this line
	init(argv + 2, argc - 2);

	// debugging 
	for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
		printf("%s\n", get_interface_ip(i));
	}

	while (1) {
		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// Sanity check
		if (len < sizeof(struct ether_hdr)) {
			printf("[ROUTER] The received packet is malformed\n");
			continue;
		}		

		// Verify if packet is for router or broadcast 
		struct ether_hdr* eth_hdr = (struct ether_hdr *) buf;
		uint8_t mac_interface[6];
		uint8_t is_broadcast = 1;

		get_interface_mac(interface, mac_interface);
		for (int i = 0; i < 6; i++) {
			if (eth_hdr->ethr_dhost[i] != 0xFF) is_broadcast = 0; 
		}
		if (memcmp(eth_hdr->ethr_dhost, mac_interface, 6) != 0 && !is_broadcast) {
			// debugging
			// printf("[ROUTER] Packet is not for me. Discarding...\n");
			// printf("[DEBUG] Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
    		// 		eth_hdr->ethr_dhost[0], eth_hdr->ethr_dhost[1], eth_hdr->ethr_dhost[2],
       		// 		eth_hdr->ethr_dhost[3], eth_hdr->ethr_dhost[4], eth_hdr->ethr_dhost[5]);
			// printf("[DEBUG] Router MAC interface: %02x:%02x:%02x:%02x:%02x:%02x\n",
			// 		mac_interface[0], mac_interface[1], mac_interface[2],
			// 		mac_interface[3], mac_interface[4], mac_interface[5]);		
			continue;
		}

		// Verify packet type
		uint16_t eth_type = ntohs(eth_hdr->ethr_type);

		if (eth_type != IPv4 && eth_type != ARP) {
			printf("[ROUTER] The received packet is neither IPv4 nor ARP\n");
			continue;
		}

		// TODO: Handle IPv4 packets : DONE 
		if (eth_type == IPv4) {
			// Verify if destination is router
			// debugging 
			printf("[ROUTER] Received IPv4 packet\n");

			struct ip_hdr* iphdr = (struct ip_hdr*)(buf + sizeof(struct ether_hdr));
			int own_destination = is_router_interface(iphdr->dest_addr); // should be 1 if the 
			// destination is an interface of the router

			uint16_t aux_check = ntohs(iphdr->checksum);

			iphdr->checksum = 0;
			if (checksum((uint16_t *)iphdr, sizeof(struct ip_hdr)) != aux_check) {
				printf("[ROUTER] Bad checksum. Discarding...\n");
				continue;
			}

			if (iphdr->ttl <= 1) {
				// TODO: Build ICMP reply : DONE
				// printf("[ROUTER] ICMP echo request is for me. Sending reply\n");
				printf("[ROUTER] ICMP packet TTL EXCEEDED\n");
				send_icmp_reply(buf, len, interface, ICMP_TIME_EXCEEDED_TYPE, ICMP_TIME_EXCEEDED_CODE, own_destination);
				continue;
			}
			if (own_destination) {
				// TODO: Build ICMP reply : DONE
				if (iphdr->proto != 1) {
					printf("[ROUTER] The packet is not ICMP. Discarding...\n");
					continue; 
				}
				printf("[ROUTER] ICMP echo request is for me. Sending reply\n");
				send_icmp_reply(buf, len, interface, ICMP_REPLY_TYPE, ICMP_REPLY_CODE, own_destination);
				continue;
			} else {
				printf("[ROUTER] ICMP echo request is not for me. Forwarding\n");
				// TODO: Forward packet : If MAC is in ARP cache then forward packet : DONE
				// Otherwise send ARP request and wait for reply : DONE  
				forward_ipv4_packet(buf, len, interface);
				continue;
			}
		}

		// TODO: Handle ARP packets : DONE 
		if (eth_type == ARP) {
			// printf("[ROUTER] Received ARP packet\n");
			struct arp_hdr* arphdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
			int own_destination = is_router_interface(arphdr->tprotoa);
			uint16_t opcode = ntohs(arphdr->opcode);

			if (opcode == 1) {
				printf("[ROUTER] Received ARP request packet\n");
				if (own_destination) {
					// TODO: Send an ARP reply : DONE
					printf("[ROUTER] The ARP request is for me. Sending reply\n");
					send_arp_reply(buf, len, interface);
					continue;
				} else {
					printf("[ROUTER] The ARP request is not for me. Discarding...\n");
					continue;
				}
			} else if (opcode == 2) {
				// TODO: Search for the original IPv4 packet. Add entry in ARP cache : DONE
				printf("[ROUTER] Received ARP reply. Searcing for original IPv4 packet\n");
				arp_table[arp_table_len].ip = arphdr->sprotoa;
				memcpy(arp_table[arp_table_len].mac, arphdr->shwa, 6);
				arp_table_len++;

				queue new_arp_pending_queue = create_queue();

				while(!queue_empty(arp_pending_queue)) {
					struct waiting_packet* saved_packet = (struct waiting_packet *) queue_deq(arp_pending_queue);
					// struct ether_hdr* aux_eth_hdr = (struct ether_hdr *)(saved_packet->buf);
					// struct ip_hdr* aux_ip_hdr = (struct ip_hdr *)(saved_packet->buf + sizeof(struct ether_hdr));

					if (saved_packet->next_hop == arphdr->sprotoa) {
						printf("[ROUTER] Found original IPv4 packet. Forwarding\n");
						forward_ipv4_packet(saved_packet->buf, saved_packet->len, saved_packet->interface);
						free(saved_packet->buf);
						free(saved_packet);
					} else  {
						queue_enq(new_arp_pending_queue, saved_packet);
					}
				}
				free(arp_pending_queue);
				arp_pending_queue = new_arp_pending_queue;
			}

		}
	}
}

