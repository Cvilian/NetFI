/* layer-tcp.cpp
 * 
 * routines for the TCP packet parsing
 *  
 * NetFI - a fast and simple tool to analyze the network flow (Internet Protocol family) 
 */

#include <stdlib.h>

#include "layer-tcp.h"
#include "layer-data.h"

namespace pump
{

    TcpLayer::TcpLayer(uint8_t* data, size_t datalen, Layer* prev_layer) : Layer(data, datalen, prev_layer)
    {
        l_proto = PROTO_TCP;
        l_opt = NULL;
        l_optcnt = 0;

        size_t optlen = getOptionLen();
        if(optlen == 0) return;

        uint8_t* opt_base = l_data + sizeof(tcp_hdr);
        while(optlen > 0)
        {
            uint8_t type = *opt_base;
            tcp_opt* curr_opt = (tcp_opt*)malloc(sizeof(tcp_opt));
            curr_opt->type = type;

            if(type == TCPOPT_EOL || type == TCPOPT_NOP)
            {
                curr_opt->len = 1;
                curr_opt->data = NULL;
                optlen--;
            }
            else
            {
                curr_opt->len = *(opt_base + 1);
                curr_opt->data = opt_base + 2;
                optlen -= curr_opt->len;
            }
            opt_base += curr_opt->len;
            curr_opt->prev = l_opt;
            l_opt = curr_opt;
            l_optcnt++;
        }
    }

    TcpLayer::~TcpLayer()
    {
        while(l_opt != NULL)
        {
            free(l_opt);
        }
    }

    void TcpLayer::dissectData()
    {
        size_t hdr_len = getHeaderLen();
        if (l_datalen <= hdr_len)
            return;

        uint8_t* payload = l_data + hdr_len;
        size_t payloadLen = l_datalen - hdr_len;
        
        // In NetFI, we don't need to parse the upper-layer (e.g., HTTP, SMTP, TLS, etc) of current one 
        l_nextlayer = new DataLayer(payload, payloadLen, this);
    }

    uint8_t* TcpLayer::getOption(uint8_t type)
    {
        tcp_opt* opt = l_opt;
        while(opt != NULL)
        {
            if(opt->type == type)
                return opt->data;
            
            opt = opt->prev;
        }
        return 0;
    }

    bool TcpLayer::isValidLayer(const uint8_t* data, size_t datalen)
    {
        const tcp_hdr* hdr = reinterpret_cast<const tcp_hdr*>(data);
        return datalen >= sizeof(tcp_hdr)
        && hdr->dataoffset >= 5
        && datalen >= hdr->dataoffset * sizeof(uint32_t);
    }

}