/* reader.h
 * 
 * routines for reading packet from a pcap file or interface
 *  
 * NetFI - a fast and simple tool to analyze the network flow (Internet Protocol family) 
 */

#ifndef PUMP_READER
#define PUMP_READER

#include <pcap.h>
#include <stdint.h>

#include "packet.h"
#include "layer-ip.h"

static const int DEFAULT_DEVMODE = 1;
static const int DEFAULT_SNAPLEN = 9000;
static const int DEFAULT_TIMEOUT = -1;

namespace pump
{

    class LiveReader;

    typedef void (*OnPacketArrival)(Packet* packet, LiveReader* lrdr, void* cookie);

    class Reader
    {

        protected:

            bool rdr_on;
            pcap_t* rdr_descriptor;

            Reader(): rdr_on(false), rdr_descriptor(NULL) {}
        
        public:

            virtual ~Reader() {}

            virtual bool open() = 0;

            virtual void close() = 0;

    };

    class PcapReader : public Reader
    {

        protected:

            char* prdr_datasrc;
            uint16_t prdr_linktype;

        public:

            PcapReader(const char* pcapfile);

            ~PcapReader() { close(); }

            static PcapReader* getReader(const char* pcapfile);

            bool open();

            bool getNextPacket(Packet& packet);

            void close();

    };

    class LiveReader : public Reader
    {

        protected:

            char* lrdr_datasrc;
            uint16_t lrdr_linktype;
            bool lrdr_on_capture;
            bool lrdr_on_stop;
            OnPacketArrival lrdr_pkt_arrival;
            void* lrdr_pkt_arrival_cookie;
            pthread_t lrdr_thread_capture;

            pcap_t* LiveInit();

            static void* captureThreadMain(void* ptr);

            static void onPacketArrival(uint8_t* user, const struct pcap_pkthdr* pkt_hdr, const uint8_t* packet);

        public:

            LiveReader(pcap_if_t* pInterface, bool calculateMTU, bool calculateMacAddress, bool calculateDefaultGateway);

            ~LiveReader() { close(); }

            bool open();

            void startCapture(OnPacketArrival onPacketArrival, void* onPacketArrivalCookie);

            void stopCapture();

            const char* getName() const { return lrdr_datasrc; }

            uint16_t getLinkType() const { return lrdr_linktype; }

            void close();

    };

    class LiveInterfaces
    {

        private:

            std::vector<LiveReader*> li_ifacelist;

            LiveInterfaces();

        public:

            static LiveInterfaces& getInstance()
            {
                static LiveInterfaces instance;
                return instance;
            }

            LiveReader* getLiveReader(const std::string& name) const;

    };

}

#endif