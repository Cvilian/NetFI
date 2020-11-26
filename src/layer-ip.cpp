/* layer-ip4.cpp
 * 
 * routines for the IPv4 packet parsing
 *  
 * NetFI - a fast and simple tool to analyze the network flow (Internet Protocol family) 
 */

#include "layer-ip.h"
#include "layer-tcp.h"
#include "layer-udp.h"
#include "layer-icmp.h"
#include "layer-data.h"

namespace pump
{

    IPv4Address::IPv4Address(const std::string& addrAsString)
    {
        if (inet_pton(AF_INET, addrAsString.data(), ad_Bytes) <= 0)
            memset(ad_Bytes, 0, sizeof(ad_Bytes));
    }

    std::string IPv4Address::toString() const
    {
        char addrBuffer[INET_ADDRSTRLEN];

        if (inet_ntop(AF_INET, toBytes(), addrBuffer, sizeof(addrBuffer)) != NULL)
            return std::string(addrBuffer);

        return std::string();
    }

    IPv4Layer::IPv4Layer(uint8_t* data, size_t datalen, Layer* prev_layer) : Layer(data, datalen, prev_layer)
    {
        l_proto = PROTO_IPv4;
        size_t totalLen = ntohs(getHeader()->total_len);

        if ((totalLen < l_datalen) && (totalLen !=0))
            l_datalen = totalLen;
    }

    bool IPv4Layer::isFragment() const
    {
        return ((getFragmentFlags() & IP_MORE_FRAGMENTS) != 0 || getFragmentOffset() != 0);
    }

    void IPv4Layer::dissectData()
    {
        size_t hdrLen = getHeaderLen();
        if (l_datalen <= hdrLen)
            return;

        ip_hdr* hdr = getHeader();

        uint8_t ipVersion = 0;

        uint8_t* payload = l_data + hdrLen;
        size_t payloadLen = l_datalen - hdrLen;

        if (isFragment())
        {
            l_nextlayer = new DataLayer(payload, payloadLen, this);
            return;
        }

        switch (hdr->proto)
        {
            case IPV4PROTO_UDP:
                if (payloadLen >= sizeof(udp_hdr))
                    l_nextlayer = new UdpLayer(payload, payloadLen, this);
                break;
            case IPV4PROTO_TCP:
                l_nextlayer = TcpLayer::isValidLayer(payload, payloadLen)
                    ? static_cast<Layer*>(new TcpLayer(payload, payloadLen, this))
                    : static_cast<Layer*>(new DataLayer(payload, payloadLen, this));
                break;
            case IPV4PROTO_ICMP:
                l_nextlayer = IcmpLayer::isValidLayer(payload, payloadLen)
                    ? static_cast<Layer*>(new IcmpLayer(payload, payloadLen, this))
                    : static_cast<Layer*>(new DataLayer(payload, payloadLen, this));
                break;
            case IPV4PROTO_IPIP:
                ipVersion = *payload >> 4;
                if (ipVersion == 4)
                    l_nextlayer = new IPv4Layer(payload, payloadLen, this);
                else
                    l_nextlayer = new DataLayer(payload, payloadLen, this);
                break;
            default:
                l_nextlayer = new DataLayer(payload, payloadLen, this);
        }
    }

    bool IPv4Layer::isValidLayer(const uint8_t* data, size_t datalen)
    {
        const ip_hdr* hdr = reinterpret_cast<const ip_hdr*>(data);
        return datalen >= sizeof(ip_hdr) && hdr->ver == 4 && hdr->hdr_len >= 5;
    }

    in_addr* sockaddr2in_addr(struct sockaddr* sa)
    {
        if (sa == NULL)
            return NULL;
        if (sa->sa_family == AF_INET)
            return &(((struct sockaddr_in*)sa)->sin_addr);
        return NULL;
    }

    void sockaddr2string(struct sockaddr* sa, char* resultString)
    {
        in_addr* ipv4Addr = sockaddr2in_addr(sa);
        if (ipv4Addr != NULL)
        {
            inet_ntop(AF_INET, &(((sockaddr_in*)sa)->sin_addr), resultString, INET_ADDRSTRLEN);
        }
        else
        {
            inet_ntop(AF_INET6, &(((sockaddr_in6*)sa)->sin6_addr), resultString, INET6_ADDRSTRLEN);
        }
    }

}