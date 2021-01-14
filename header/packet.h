/* packet.h
 * 
 * basic structure of a packet
 *  
 * NetFI - a fast and simple tool to analyze the network flow 
 */

#ifndef PUMP_PACKET
#define PUMP_PACKET

#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>
#include <vector>

#include "layer.h"

#define LINKTYPE_ETHERNET          1

#define MAX_PACKET_SIZE        65536

namespace pump
{

    class Packet
    {

        protected:
            
            uint8_t* pk_data;
            uint16_t pk_datalen;
            bool pk_delete_data;
            uint16_t pk_linktype;
            uint8_t pk_proto_types;
            timeval pk_timestamp;
            Layer* pk_firstlayer;
            Layer* pk_lastlayer;

            void Init();

            Layer* initLayer(uint16_t linktype);

        public:

            Packet();

            Packet(const uint8_t* data, uint16_t datalen, timeval ts, bool delete_rawdata, uint16_t layertype = LINKTYPE_ETHERNET);

            ~Packet() { clearData(); }

            bool setData(const uint8_t* data, uint16_t datalen, timeval ts, uint16_t layertype = LINKTYPE_ETHERNET);

            template<class TLayer> TLayer* getLayer() const;

            template<class TLayer> TLayer* getNextLayer(Layer* layertype) const;

            const uint8_t* getData() const { return pk_data; }

            uint16_t getDataLen() const { return pk_datalen; }

            timeval getTimeStamp() const { return pk_timestamp; }

            uint8_t getProtocolTypes() const { return pk_proto_types; }

            bool isTypeOf(uint8_t protocol) const { return pk_proto_types & protocol; }

            void clearData();

    };

    template<class T> T* Packet::getLayer() const
    {
        if (dynamic_cast<T*>(pk_firstlayer) != NULL)
            return (T*)pk_firstlayer;

        return getNextLayer<T>(pk_firstlayer);
    }

    template<class T> T* Packet::getNextLayer(Layer* layertype) const
    {
        if (layertype == NULL)
            return NULL;

        Layer* curr_layer = layertype->getNextLayer();
        while ((curr_layer != NULL) && (dynamic_cast<T*>(curr_layer) == NULL))
        {
            curr_layer = curr_layer->getNextLayer();
        }

        return (T*)curr_layer;
    }

}

#endif