/* layer-eth.cpp
 * 
 * routines for the ethernet packet parsing
 *  
 * NetFI - a fast and simple tool to analyze the network flow (Internet Protocol family) 
 */

#include <string.h>
#include <arpa/inet.h>

#include "layer-eth.h"
#include "layer-ip.h"
#include "layer-data.h"

namespace pump
{
    
    void EthLayer::dissectData()
    {
        if (l_datalen <= sizeof(eth_hdr))
            return;

        eth_hdr* hdr = getHeader();
        uint8_t* payload = l_data + sizeof(eth_hdr);
        size_t payloadLen = l_datalen - sizeof(eth_hdr);

        switch (be16toh(hdr->type))
        {
            case ETHERTYPE_IP:
                l_nextlayer = IPv4Layer::isValidLayer(payload, payloadLen)
                    ? static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this))
                    : static_cast<Layer*>(new DataLayer(payload, payloadLen, this));
                break;
            default:
                l_nextlayer = new DataLayer(payload, payloadLen, this);
        }
    }

}