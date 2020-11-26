/* packet.cpp
 * 
 * basic structure of a packet
 *  
 * NetFI - a fast and simple tool to analyze the network flow (Internet Protocol family) 
 */

#include <endian.h>

#include <vector>

#include "layer-eth.h"
#include "layer-ip.h" 
#include "layer-data.h"
#include "packet.h"

namespace pump
{

    void Packet::Init()
    {
        pk_datalen = 0;
        pk_delete_data = true;
        pk_linktype = LINKTYPE_ETHERNET;
        pk_firstlayer = NULL;
        pk_lastlayer = NULL;
        pk_data = 0;
    }

    Layer* Packet::initLayer(uint16_t linktype)
    {
        if (pk_datalen == 0)
            return NULL;

        if (linktype == LINKTYPE_ETHERNET)
        {
            if ((unsigned long)pk_datalen >= sizeof(eth_hdr))
            {
                uint16_t ethTypeOrLength = be16toh(*(uint16_t*)(pk_data + 12));
                if (ethTypeOrLength > (uint16_t)0x5dc || ethTypeOrLength != 0)
                {
                    return new EthLayer(pk_data, pk_datalen, NULL);
                }	
            }
        }

        return new DataLayer(pk_data, pk_datalen, NULL);
    }

    Packet::Packet()
    {
        Init();
    }

    Packet::Packet(const uint8_t* data, uint16_t datalen, timeval ts, bool delete_rawdata, uint16_t layertype)
    {
        Init();
        pk_delete_data = delete_rawdata;
        setData(data, datalen, ts, layertype);
    }

    bool Packet::setData(const uint8_t* data, uint16_t datalen, timeval ts, uint16_t layertype)
    {
        clearData();

        pk_data = (uint8_t*)data;
        pk_datalen = datalen;
        pk_timestamp = ts;
        pk_linktype = layertype;
        pk_firstlayer = NULL;
        pk_lastlayer = NULL;
        pk_proto_types = PROTO_UNKNOWN;

        if (pk_data == 0)
            return true;

        pk_firstlayer = initLayer(pk_linktype);

        pk_lastlayer = pk_firstlayer;
        Layer* curr_layer = pk_firstlayer;

        while (curr_layer != NULL)
        {
            pk_proto_types |= curr_layer->getProtocol();
            curr_layer->dissectData();
            curr_layer = curr_layer->getNextLayer();
            if (curr_layer != NULL)
                pk_lastlayer = curr_layer;
        }
    
        if (pk_lastlayer != NULL)
        {
            uint16_t trailer_len = (uint16_t)((pk_data + pk_datalen) - (pk_lastlayer->getData() + pk_lastlayer->getDataLen()));

            if (trailer_len > 0)
            {
                TrailerLayer* trailerLayer = new TrailerLayer((uint8_t*)(pk_lastlayer->getData() + pk_lastlayer->getDataLen()), trailer_len, pk_lastlayer);

                pk_lastlayer->setNextLayer(trailerLayer);
                pk_lastlayer = trailerLayer;
                pk_proto_types |= trailerLayer->getProtocol();
            }
        }

        return true;
    }

    void Packet::clearData()
    {
        if (pk_data != 0 && pk_delete_data)
        {
            delete[] pk_data;
        }
    }

}