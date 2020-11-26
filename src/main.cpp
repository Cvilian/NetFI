/* main.cpp
 * 
 * routines for capturing a series of SSL/TLS record data from TCP data streams
 *  
 * NetFI - a fast and simple tool to analyze the network flow (Internet Protocol family) 
 */

#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h> 

#include "utils.h"
#include "reader.h"
#include "handler.h"
#include "tracker.h"

#define EXIT_WITH_OPTERROR(reason, ...) do { \
	printf("\n " reason "\n", ## __VA_ARGS__); \
    printUsage(); \
	exit(1); \
} while(0)

timeval init_tv;

static struct option NetFIOptions[] =
{
    {"count",  required_argument, 0, 'c'},
    {"duration",  required_argument, 0, 'd'},
    {"interface",  required_argument, 0, 'i'},
    {"input-file",  required_argument, 0, 'r'},
    {"output-file", required_argument, 0, 'w'},
    {"quite-mode", no_argument, 0, 'q'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};

struct PacketArrivedData
{
    pump::Tracker* tracker;
    struct pump::CaptureConfig* config;
};

void printUsage()
{
    printf("\nNetFI - a fast and simple tool to analyze the network flow (Internet Protocol family)\n"
    "See https://github.com/Cvilian/NetFI for more information\n\n"
    "Usage: NetFI [options] ...\n"
    "Capture packets:\n"
    "    -i <interface>   : Name of the network interface\n"
    "    -r <input-file>  : Read packet data from <input-file>\n"
    "Capture stop conditions:\n"
    "    -c <count>       : Set the maximum number of packets to read\n"
    "    -d <duration>    : Stop after <duration> seconds\n"
    "Processing:\n"
    "    -q               : Print less-verbose flow information\n"
    "    -s               : Mark a N/A value as '-', instead of a zero value\n"
    "Output:\n"
    "    -w <output-file> : Write all flow-statistical info to <output-file>\n"
    "                       (or write its results to stdout)\n"
    "Others:\n"
    "    -h               : Displays this help message and exits\n"
	
    "-------------------------\n");
    exit(0);
}

void packetArrive(pump::Packet* packet, pump::LiveReader* rdr, void* cookie)
{
    PacketArrivedData* data = (PacketArrivedData*)cookie;
    data->tracker->parsePacket(packet, data->config);
}

void doNetFIOnLive(pump::LiveReader* rdr, struct pump::CaptureConfig* config)
{
    if (!rdr->open())
        EXIT_WITH_CONFERROR("###ERROR : Could not open the device");

    PacketArrivedData data;
    pump::Tracker tracker(init_tv);
    data.tracker = &tracker;
    data.config = config;
    rdr->startCapture(packetArrive, &data);

    // run in an endless loop until the user presses ctrl+c
    while(!tracker.isTerminated())
        sleep(1);

    rdr->stopCapture();
    rdr->close();

    if(!(config->quitemode)) printf("\n");
    pump::print_progressM(tracker.getTotalPacket());
    printf(" **%lu Bytes**\n", tracker.getTotalByteLen());

    if(config->outputFileTo != "")
    {
        tracker.registerEvent();
        tracker.saveStats(config);
    }
}

void doNetFIOnPcap(std::string pcapFile, struct pump::CaptureConfig* config)
{

    pump::PcapReader rdr(pcapFile.c_str());
    if (!rdr.open())
        EXIT_WITH_CONFERROR("###ERROR : Could not open input pcap file");

    pump::Tracker tracker(init_tv);
    pump::Packet packet;

    while(rdr.getNextPacket(packet) && !tracker.isTerminated())
    {
        tracker.parsePacket(&packet, config);
    }

    rdr.close();

    if(!(config->quitemode)) printf("\n");
    pump::print_progressM(tracker.getTotalPacket());
    printf(" **%lu Bytes**\n", tracker.getTotalByteLen());

    if(config->outputFileTo != "")
    {
        tracker.registerEvent();
        tracker.saveStats(config);
    }
}

int main(int argc, char* argv[])
{
    gettimeofday(&init_tv, NULL);

    if (getuid())
        EXIT_WITH_CONFERROR("###ERROR : Running NetFI requires root privileges!\n");

    std::string readPacketsFromPcap = "";
    std::string readPacketsFromInterface = "";
    std::string outputFileTo = "";

    int optionIndex = 0;
    uint32_t maxPacket = IN_LIMIT;
    uint32_t maxTime = IN_LIMIT;
    bool quitemode = false;
    bool mark_null = false;
    char opt = 0;

    while((opt = getopt_long (argc, argv, "c:d:i:r:w:qsh", NetFIOptions, &optionIndex)) != -1)
    {
        switch (opt)
        {
            case 0:
                break;
            case 'c':
                maxPacket = atoi(optarg);
                break;
            case 'd':
                maxTime = atoi(optarg);
                break;
            case 'i':
                readPacketsFromInterface = optarg;
                break;
            case 'r':
                readPacketsFromPcap = optarg;
                break;
            case 'w':
                outputFileTo = optarg;
                break;
            case 'q':
                quitemode = true;
                break;
            case 's':
                mark_null = true;
                break;
            case 'h':
                printUsage();
                break;
            default:
                printUsage();
                exit(-1);
        }
    }

    // if no input pcap file or network interface was provided - exit with error
    if (readPacketsFromPcap == "" && readPacketsFromInterface == "")
        EXIT_WITH_OPTERROR("###ERROR : Neither interface nor input pcap file were provided");

    // you should choose only one option : pcap or interface - exit with error
    if (readPacketsFromPcap != "" && readPacketsFromInterface != "")
        EXIT_WITH_OPTERROR("###ERROR : Choose only one option, pcap or interface");

    if (maxPacket <= 0)
        EXIT_WITH_OPTERROR("###ERROR : #Packet can't be a non-positive integer");

    if (maxTime <= 0)
        EXIT_WITH_OPTERROR("###ERROR : Duration can't be a non-positive integer");

    pump::CaptureConfig config = {
        .maxPacket = maxPacket,
        .maxTime = maxTime,
        .quitemode = quitemode,
        .mark_null = mark_null,
        .outputFileTo = outputFileTo
    };

    if(access(save_dir.c_str(), 0) == -1)
        mkdir(save_dir.c_str(), 0777);

    if (readPacketsFromPcap != "")
    {
        doNetFIOnPcap(readPacketsFromPcap, &config);
    }
    else
    {
        pump::LiveReader* rdr = pump::LiveInterfaces::getInstance().getLiveReader(readPacketsFromInterface);

        if (rdr == NULL)
            EXIT_WITH_CONFERROR("###ERROR : Couldn't find interface by provided name");

        doNetFIOnLive(rdr, &config);
    }
    //pump::clearNetFI();
    printf(" **All Done**\n");
    WRITE_LOG("===Process Finished");
    return 0;
}