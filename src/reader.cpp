/* reader.cpp
 * 
 * routines for reading packet from a pcap file or interface
 *  
 * NetFI - a fast and simple tool to analyze the network flow (Internet Protocol family) 
 */

#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "reader.h"
#include "handler.h"

namespace pump
{

    char msg[PCAP_ERRBUF_SIZE];

    PcapReader::PcapReader(const char* pcapfile) : Reader()
    {
        int pcapname_len = strlen(pcapfile) + 1;
        prdr_datasrc = (char*)malloc(pcapname_len);
        strncpy(prdr_datasrc, pcapfile, pcapname_len);
    }

    PcapReader* PcapReader::getReader(const char* pcapfile)
    {
        const char* file_extension = strrchr(pcapfile, '.');

        if (file_extension == NULL || strcmp(file_extension, ".pcap") != 0)
            EXIT_WITH_CONFERROR("###ERROR : File extension should be a .pcap");

        return new PcapReader(pcapfile);
    }

    bool PcapReader::open()
    {
        if (rdr_descriptor != NULL)
        {
            WRITE_LOG("###WARNING : PcapReader is already opened");
            return true;
        }

        char errbuf[PCAP_ERRBUF_SIZE];

        rdr_descriptor = pcap_open_offline(prdr_datasrc, errbuf);
        if (rdr_descriptor == NULL)
        {
            EXIT_WITH_CONFERROR("###ERROR : Could not open a pcap file by provided name");
        }

        prdr_linktype = static_cast<uint16_t>(pcap_datalink(rdr_descriptor));

        rdr_on = true;
        WRITE_LOG("===PcapReader is now scheduled to scan '%s'", prdr_datasrc);

        return true;
    }
    
    bool PcapReader::getNextPacket(Packet& packet)
    {
        if (rdr_descriptor == NULL)
        {
            EXIT_WITH_RUNERROR("###ERROR : PcapReader '%s' is not opened", prdr_datasrc);
        }

        pcap_pkthdr pkthdr;
        const uint8_t* rawdata = pcap_next(rdr_descriptor, &pkthdr);

        if (rawdata == NULL)
        {
            WRITE_LOG("===PcapReader '%s' encountered End-of-File (EOF)", prdr_datasrc);
            return false;
        }
        
        uint8_t* data = new uint8_t[pkthdr.caplen];
        memcpy(data, rawdata, pkthdr.caplen);

        if (!packet.setData(data, pkthdr.caplen, pkthdr.ts, static_cast<uint16_t>(prdr_linktype)))
        {
            EXIT_WITH_RUNERROR("###ERROR : PcapReader '%s' is failed to read raw packet data", prdr_datasrc);
        }

        return true;
    }

    void PcapReader::close()
    {
        if (prdr_datasrc != NULL)
        {
            free(prdr_datasrc);
        }

        if (rdr_descriptor != NULL)
        {
            pcap_close(rdr_descriptor);
            rdr_descriptor = NULL;
        }

        rdr_on = false;
    }

    pcap_t* LiveReader::LiveInit()
    {
        pcap_t* pcap = pcap_create(lrdr_datasrc, msg);
        if (!pcap)
        {
            EXIT_WITH_CONFERROR("###ERROR : Could not access the network interface : %s", msg); 
        }
        
        if (pcap_set_snaplen(pcap, DEFAULT_SNAPLEN) != 0)
        {
            EXIT_WITH_CONFERROR("###ERROR : Could not access the network interface : %s", pcap_geterr(pcap)); 
        }

        if (pcap_set_promisc(pcap, DEFAULT_DEVMODE) != 0)
        {
            EXIT_WITH_CONFERROR("###ERROR : Could not access the network interface : %s", pcap_geterr(pcap));
        }

        if (pcap_set_timeout(pcap, DEFAULT_TIMEOUT) != 0)
        {
            EXIT_WITH_CONFERROR("###ERROR : Could not access the network interface : %s", pcap_geterr(pcap));
        }

        if (pcap_activate(pcap) != 0)
        {
            EXIT_WITH_CONFERROR("###ERROR : Could not access the network interface : %s", pcap_geterr(pcap));
        }

        if (pcap)
        {
            int dlt = pcap_datalink(pcap);
            lrdr_linktype = (uint16_t)dlt;
        }
        return pcap;
    }

    void* LiveReader::captureThreadMain(void* ptr)
    {
        LiveReader* rdr = (LiveReader*)ptr;

        if (rdr == NULL)
            exit(1);

        while (!rdr->lrdr_on_stop)
        {
            pcap_dispatch(rdr->rdr_descriptor, -1, onPacketArrival, (uint8_t*)rdr);
        }

        return 0;
    }

    void LiveReader::onPacketArrival(uint8_t* user, const struct pcap_pkthdr* pkt_hdr, const uint8_t* packet)
    {
        LiveReader* rdr = (LiveReader*)user;

        if (rdr == NULL)
            exit(1);

        Packet Packet(packet, pkt_hdr->caplen, pkt_hdr->ts, false, rdr->getLinkType());

        if (rdr->lrdr_pkt_arrival != NULL)
            rdr->lrdr_pkt_arrival(&Packet, rdr, rdr->lrdr_pkt_arrival_cookie);
    }

    LiveReader::LiveReader(pcap_if_t* pInterface, bool calculateMTU, bool calculateMacAddress, bool calculateDefaultGateway) : Reader()
    {
        lrdr_datasrc = NULL;
        lrdr_linktype = LINKTYPE_ETHERNET;

        int ifacename_len = strlen(pInterface->name)+1;
        lrdr_datasrc = (char*)malloc(ifacename_len);
        strncpy((char*)lrdr_datasrc, pInterface->name, ifacename_len);

        while (pInterface->addresses != NULL)
        {
            pInterface->addresses = pInterface->addresses->next;
            if (pInterface->addresses != NULL && pInterface->addresses->addr != NULL)
            {
                char addrAsString[INET6_ADDRSTRLEN];
                sockaddr2string(pInterface->addresses->addr, addrAsString);
            }
        }
        lrdr_on_capture = false;
        lrdr_on_stop = false;
        lrdr_pkt_arrival = NULL;
        lrdr_pkt_arrival_cookie = NULL;
    }
    
    bool LiveReader::open()
    {
        if (rdr_descriptor != NULL)
        {
            WRITE_LOG("###WARNING : LiveReader is already opened");
            return true;
        }

        rdr_descriptor = LiveInit();
        if (rdr_descriptor == NULL)
        {
            EXIT_WITH_CONFERROR("###ERROR : Could not find interface by provided name");
        }

        rdr_on = true;
        WRITE_LOG("===PcapReader is now scheduled to scan '%s'", lrdr_datasrc);
        return true;
    }

    void LiveReader::startCapture(OnPacketArrival onPacketArrival, void* onPacketArrivalCookie)
    {
        if (!rdr_on || rdr_descriptor == NULL)
        {
            EXIT_WITH_RUNERROR("###ERROR : LiveReader '%s' is not opened", lrdr_datasrc);
        }

        if (lrdr_on_capture)
        {
            EXIT_WITH_RUNERROR("###ERROR : LiveReader '%s' is already capturing packets", lrdr_datasrc);
        }

        lrdr_pkt_arrival = onPacketArrival;
        lrdr_pkt_arrival_cookie = onPacketArrivalCookie;

        int err = pthread_create(&lrdr_thread_capture, NULL, captureThreadMain, (void*)this);
        if (err != 0)
        {
            EXIT_WITH_RUNERROR("###ERROR : Could not create real-time capture thread for LiveReader '%s'", lrdr_datasrc);
        }
        lrdr_on_capture = true;
    }

    void LiveReader::stopCapture()
    {
        lrdr_on_stop = true;
        if (lrdr_on_capture)
        {
            pthread_join(lrdr_thread_capture, NULL);
            lrdr_on_capture = false;
        }

        sleep(1);
        lrdr_on_stop = false;
    }

    void LiveReader::close()
    {
        if (lrdr_datasrc != NULL)
        {
            free(lrdr_datasrc);
        }

        if (rdr_descriptor != NULL)
        {
            pcap_close(rdr_descriptor);
            rdr_descriptor = NULL;
        }

        rdr_on = false;
    }

    LiveInterfaces::LiveInterfaces()
    {
        pcap_if_t* iface_list;

        if (pcap_findalldevs(&iface_list, msg) < 0)
        {
            EXIT_WITH_CONFERROR("###ERROR : Could not find activated network interfaces : %s", msg);
        }

        pcap_if_t* curr_iface = iface_list;
        while (curr_iface != NULL)
        {
            LiveReader* dev = new LiveReader(curr_iface, true, true, true);
            curr_iface = curr_iface->next;
            li_ifacelist.insert(li_ifacelist.end(), dev);
        }

        pcap_freealldevs(curr_iface);
    }

    LiveReader* LiveInterfaces::getLiveReader(const std::string& name) const
    {
        WRITE_LOG("===Search all live interfaces");
        for(std::vector<LiveReader*>::const_iterator dit = li_ifacelist.begin(); dit != li_ifacelist.end(); dit++)
        {
            if (name == std::string((*dit)->getName()))
                return *dit;
        }

        return NULL;
    }
}