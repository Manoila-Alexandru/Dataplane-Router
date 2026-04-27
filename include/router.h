#include <stdint.h>

enum PACKET {
	IPv4 = 0x0800,
	ARP = 0x0806
};

enum ICMP {
	ICMP_REPLY_TYPE = 0,
	ICMP_REPLY_CODE = 0,
	ICMP_TIME_EXCEEDED_TYPE = 11,
	ICMP_TIME_EXCEEDED_CODE = 0,
	ICMP_DESTINATION_UNREACHABLE_TYPE = 3,
	ICMP_DESTINATION_UNREACHABLE_CODE = 0
};

// Packets that go in the pending arp queue since it's generic
struct waiting_packet {
	size_t len; 
	size_t interface;
	char* buf; 
	uint32_t next_hop;
};

// Return 1 if the destination is an interface of the router. Otherwise 0
int is_router_interface(uint32_t dest_addr);

// Compare routing table entries - ascending for prefix and mask
int compare_rtable(const void* route1, const void* route2);

/** 
 * @brief LPM algorithm to get best route. Returns NULL for no match. Uses binary search 
 * over a sorted routing table.
 * @param dest_ip Destination ip adress. PASS IT IN NETWORK ORDER
 */
struct route_table_entry* get_best_route(uint32_t dest_ip, struct route_table_entry* rt_table, int rt_table_len);

// Returns the arp cache entry of dest_ip. If it doesn't exist return NULL
struct arp_table_entry* get_arp_entry(uint32_t dest_ip);

/**
 * @brief Sends an arp request to solve ip_dest_addr 
 * @param ip_dest_addr Destination ip address - PASS IT IN NETWORK ORDER
 * @param interface The index of the interface on which the request will be sent 
 */ 
void send_arp_request(uint32_t ip_dest_addr, size_t interface);

/**
 * @brief Sends an arp reply if the request is an interface of the router
 * @param buf Previous packet
 * @param len buf size in bytes 
 * @param interface the interface on which buf came
*/
void send_arp_reply(char* buf, size_t len, size_t interface);

/** 
 * @brief Builds and sends an ICMP reply based on the previous IPv4 packet.
 * @param buf Previous packet
 * @param len buf size in bytes 
 * @param interface the interface on which buf came 
 * @param type type of ICMP reply: icmp echo reply, time exceeded, or host unreachable
 * @param own_destination 1 if the original packet's destination ip address is an interface of the router.
 * Otherwise 0
 */
void send_icmp_reply(char* buf, size_t len, size_t interface, uint8_t type, uint8_t code, int own_destination);

/**
 * @brief  Forwards the ipv4 packet on the best route based on the previous packet
 * @param buf Previous packet
 * @param len buf size in bytes 
 * @param interface the interface on which buf came
*/
void forward_ipv4_packet(char* buf, size_t len, size_t interface);





