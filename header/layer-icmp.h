/* layer-icmp.h
 *
 * routines for the ICMP packet parsing
 *  
 * NetFI - a fast and simple tool to analyze the network flow 
 */

#ifndef PUMP_LAYER_ICMP
#define PUMP_LAYER_ICMP

#include "layer.h"
#include "layer-ip.h"

#define ICMP_ECHO_REPLY               0
#define ICMP_DEST_UNREACHABLE         3
#define ICMP_REDIRECT                 5
#define ICMP_ECHO_REQUEST             8
#define ICMP_ROUTER_ADV               9
#define ICMP_ROUTER_SOL              10
#define ICMP_TIME_EXCEEDED           11
#define ICMP_PARAM_PROBLEM           12
#define ICMP_TIMESTAMP_REQUEST       13
#define ICMP_TIMESTAMP_REPLY         14

#define ICMP_NET_UNREACHABLE                 0
#define ICMP_HOST_UNREACHABLE                1
#define ICMP_PROTO_UNREACHABLE               2
#define ICMP_PORT_UNREACHABLE                3
#define ICMP_DEST_HOST_PROHIBITED           10
#define ICMP_COMMUNICATION_PROHIBITED       13

namespace pump
{

	typedef struct _icmp_hdr
	{
		uint8_t	 type;
		uint8_t	 code;
		uint16_t checksum;
	} icmp_hdr;

    typedef struct : icmp_hdr
    {
        uint16_t unused;
        uint16_t next_hop_mtu;
    } icmp_dest_unreachable;    

    typedef struct : icmp_hdr
    {
        uint32_t gateway_addr;
    } icmp_redirect;

    typedef struct : icmp_hdr
    {
        uint8_t  adv_cnt;
        uint8_t  addr_entry_size;
        uint16_t lifetime;
    } icmp_router_adv_hdr;

    typedef struct : icmp_hdr
    {
        uint32_t unused;
    } icmp_time_exceeded;

    typedef struct : icmp_hdr
    {
        uint8_t  pointer;
        uint8_t  unused1;
        uint16_t unused2;
    } icmp_param_problem;

    typedef struct : icmp_hdr
    {
        uint16_t id;
        uint16_t sequence;
        uint32_t original_ts;
        uint32_t receive_ts;
        uint32_t transmit_ts;
    } icmp_ts;

    struct icmp_router_addr
    {
        uint32_t router_addr;
        uint32_t pref;
        void setRouterAddress(IPv4Address addr, uint32_t pref);
        IPv4Address getAddress() const { return router_addr; }
    };

    struct icmp_router_adv
    {
        icmp_router_adv_hdr* hdr;
        icmp_router_addr* getRouterAddr(int idx) const;
    };

    class IcmpLayer : public Layer
    {

        private:
		    mutable icmp_router_adv icmpl_router_adv_data;

        public:

            IcmpLayer(uint8_t* data, size_t datalen, Layer* prev_layer) : Layer(data, datalen, prev_layer) { l_proto = PROTO_ICMP; }

            virtual ~IcmpLayer() {};

            void dissectData();

            icmp_hdr* getHeader() const { return (icmp_hdr*)l_data; }

            size_t getHeaderLen() const;

            uint8_t getMessageType() const {return getHeader()->type; }

            uint8_t getMessageCode() const {return getHeader()->code; }

            icmp_router_adv* getRouterAdvData() const;

            static bool isValidLayer(const uint8_t* data, size_t datalen);

    };

}

#endif