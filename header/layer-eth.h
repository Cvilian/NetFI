/* layer-eth.h
 *
 * routines for the ethernet packet parsing
 *  
 * NetFI - a fast and simple tool to analyze the network flow (Internet Protocol family) 
 */

#ifndef PUMP_LAYER_ETH
#define PUMP_LAYER_ETH

#include <string.h>

#include <map>

#include "layer.h"

#define	ETHERTYPE_IP       0x0800

#define ETHERECN_ECT0       0x1
#define ETHERECN_ECT1       0x2
#define ETHERECN_CE         0x3

namespace pump
{

    typedef struct _eth_hdr
    {
        uint8_t dst[6];
        uint8_t src[6];
        uint16_t type;
    } eth_hdr;
    
    class EthLayer : public Layer
    {

        public:

            EthLayer(uint8_t* data, size_t datalen, Layer* prev_layer) : Layer(data, datalen, prev_layer) { l_proto = PROTO_ETHERNET; }

            void dissectData();

            eth_hdr* getHeader() const { return (eth_hdr*)l_data; }

            size_t getHeaderLen() const { return sizeof(eth_hdr); }

            bool isValidLayer(const uint8_t* data, size_t datalen);

    };

}

#endif