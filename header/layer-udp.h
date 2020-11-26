/* layer-udp.h
 *
 * routines for the UDP packet parsing
 *  
 * NetFI - a fast and simple tool to analyze the network flow (Internet Protocol family) 
 */

#ifndef PUMP_LAYER_UDP
#define PUMP_LAYER_UDP

#include "layer.h"

namespace pump
{
	
	typedef	struct _udp_hdr 
    {
		uint16_t sport;
		uint16_t dport;
		uint16_t ulen;
		uint16_t checksum;
	} udp_hdr;

    class UdpLayer : public Layer
    {

        public:

            UdpLayer(uint8_t* data, size_t datalen, Layer* prev_layer) : Layer(data, datalen, prev_layer) { l_proto = PROTO_UDP; }

            void dissectData();

            udp_hdr* getHeader() const { return (udp_hdr*)l_data; }

            size_t getHeaderLen() const { return sizeof(udp_hdr); }

    };
    
}

#endif