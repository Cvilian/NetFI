/* layer.h
 *
 * basic structure of a protocol layer
 *  
 * NetFI - a fast and simple tool to analyze the network flow 
 */

#ifndef PUMP_LAYER
#define PUMP_LAYER

#include <stdio.h>
#include <stdint.h>

#define PROTO_UNKNOWN        0x00
#define PROTO_ETHERNET       0x01
#define PROTO_IPv4           0x02
#define PROTO_TCP            0x04
#define PROTO_UDP            0x08
#define PROTO_ICMP           0x10
#define PROTO_DATA           0x20
#define PROTO_TRAILER        0x40

namespace pump
{

    class Layer
    {

        protected:
        
            uint8_t* l_data;
            size_t l_datalen;
            uint8_t l_proto;
            Layer* l_nextlayer;
            Layer* l_prevlayer;

        public:

            Layer(uint8_t* data, size_t datalen, Layer* prev_layer) :
                l_data(data), l_datalen(datalen), l_proto(PROTO_UNKNOWN), l_nextlayer(NULL), l_prevlayer(prev_layer) {}

            virtual ~Layer() {};

            void setNextLayer(Layer* nextLayer) { l_nextlayer = nextLayer; }

            virtual void dissectData() = 0;

            Layer* getNextLayer() const { return l_nextlayer; }

            Layer* getPrevLayer() const { return l_prevlayer; }

            uint64_t getProtocol() const { return l_proto; }

            uint8_t* getData() const { return l_data; }

            size_t getDataLen() const { return l_datalen; }

            uint8_t* getLayerPayload() const { return l_data + getHeaderLen(); }

            size_t getLayerPayloadSize() const { return l_datalen - getHeaderLen(); }

            virtual size_t getHeaderLen() const = 0;

    };

}

#endif