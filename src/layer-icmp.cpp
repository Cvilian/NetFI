/* layer-icmp.cpp
 *
 * routines for the ICMP packet parsing
 *  
 * NetFI - a fast and simple tool to analyze the network flow (Internet Protocol family) 
 */

#include "layer-ip.h"
#include "layer-icmp.h"
#include "layer-data.h"

namespace pump
{

    void IcmpLayer::dissectData()
    {
        size_t hd_len = getHeaderLen();

        switch (getMessageType())
        {
            case ICMP_DEST_UNREACHABLE:
            case ICMP_TIME_EXCEEDED:
            case ICMP_REDIRECT:
            case ICMP_PARAM_PROBLEM:
                l_nextlayer = IPv4Layer::isValidLayer(l_data + hd_len, l_datalen - hd_len)
                    ? static_cast<Layer*>(new IPv4Layer(l_data + hd_len, l_datalen - hd_len, this))
                    : static_cast<Layer*>(new DataLayer(l_data + hd_len, l_datalen - hd_len, this));
                return;
            default:
                if (l_datalen > hd_len)
                    l_nextlayer = new DataLayer(l_data + hd_len, l_datalen - hd_len, this);
                return;
        }
    }

    size_t IcmpLayer::getHeaderLen() const
    {
        uint8_t type = getMessageType();
        size_t router_adv_size = 0;

        switch (type)
        {
            case ICMP_ECHO_REQUEST:
            case ICMP_ECHO_REPLY:
                return l_datalen;
            case ICMP_TIMESTAMP_REQUEST:
            case ICMP_TIMESTAMP_REPLY:
                return sizeof(icmp_ts);
            case ICMP_DEST_UNREACHABLE:
                return sizeof(icmp_dest_unreachable);
            case ICMP_REDIRECT:
                return sizeof(icmp_redirect);
            case ICMP_TIME_EXCEEDED:
                return sizeof(icmp_time_exceeded);
            case ICMP_PARAM_PROBLEM:
                return sizeof(icmp_param_problem);
            case ICMP_ROUTER_ADV:
                router_adv_size = sizeof(icmp_router_adv_hdr) + (getRouterAdvData()->hdr->adv_cnt*sizeof(icmp_router_addr));
                if (router_adv_size > l_datalen)
                    return l_datalen;
                return router_adv_size;
            default:
                return sizeof(icmp_hdr);
        }
    }

    icmp_router_adv* IcmpLayer::getRouterAdvData() const
    {
        icmpl_router_adv_data.hdr = (icmp_router_adv_hdr*)l_data;

        return &icmpl_router_adv_data;
    }

    bool IcmpLayer::isValidLayer(const uint8_t* data, size_t datalen)
    {
        if (datalen < sizeof(icmp_hdr))
            return false;

        uint8_t type = data[0];

        switch (type)
        {
            case ICMP_ECHO_REPLY:
                return true;
            case ICMP_DEST_UNREACHABLE :
                return datalen >= sizeof(icmp_dest_unreachable);
            case ICMP_REDIRECT :
                return datalen >= sizeof(icmp_redirect);
            case ICMP_ECHO_REQUEST :
                return true;
            case ICMP_ROUTER_ADV:
                return datalen >= sizeof(icmp_router_adv_hdr);
            case ICMP_ROUTER_SOL:
                return true;
            case ICMP_TIME_EXCEEDED:
                return datalen >= sizeof(icmp_time_exceeded);
            case ICMP_PARAM_PROBLEM:
                return datalen >= sizeof(icmp_param_problem);
            case ICMP_TIMESTAMP_REQUEST:
                return datalen >= sizeof(icmp_ts);
            case ICMP_TIMESTAMP_REPLY:
                return datalen >= sizeof(icmp_ts);
            default:
                return false;
        }
    }

}