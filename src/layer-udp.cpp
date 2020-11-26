/* layer-udp.cpp
 * 
 * routines for the UDP packet parsing
 *  
 * NetFI - a fast and simple tool to analyze the network flow (Internet Protocol family) 
 */

#include "layer-udp.h"
#include "layer-data.h"

namespace pump
{

    void UdpLayer::dissectData()
    {
        size_t hdr_len = getHeaderLen();
        if (l_datalen <= hdr_len)
            return;

        uint8_t* payload = l_data + hdr_len;
        size_t payloadLen = l_datalen - hdr_len;
        
        // In NetFI, we don't need to parse the upper-layer (e.g., DHCP, DNS, etc) of current one 
        l_nextlayer = new DataLayer(payload, payloadLen, this);
    }

}