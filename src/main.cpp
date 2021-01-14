/* main.cpp
 * 
 * routines for capturing a series of SSL/TLS record data from TCP data streams
 *  
 * NetFI - a fast and simple tool to analyze the network flow 
 */

#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h> 

#include "utils.h"
#include "reader.h"
#include "handler.h"
#include "tracker.h"

/* Terminate this program when bad options are given */
#define EXIT_WITH_OPTERROR(reason, ...) do { \
	printf("\n " reason "\n", ## __VA_ARGS__); \
    printUsage(); \
	exit(1); \
} while(0)

struct timeval init_tv;

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

/* Structure to handle the packet dump */
struct PacketArrivedData
{
    pump::Tracker* tracker;
    struct pump::CaptureConfig* config;
};

/* Print help and exit */
void printUsage()
{
    printf("\nNetFI - a fast and simple tool to analyze the network flow\n"
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

/* Callback invoked whenever the reader has seen a packet */
void packetArrive(pump::Packet* packet, pump::LiveReader* rdr, void* cookie)
{
    PacketArrivedData* data = (PacketArrivedData*)cookie;
    data->tracker->parsePacket(packet, data->config);
}

/* Start gathering stat info from the discovered network interface */
void doNetFIOnLive(pump::LiveReader* rdr, struct pump::CaptureConfig* config)
{
    // Open the network interface to capture from it
    if (!rdr->open())
        EXIT_WITH_CONFERROR("###ERROR : Could not open the device");

    PacketArrivedData data;
    pump::Tracker tracker(init_tv);
    data.tracker = &tracker;
    data.config = config;
    rdr->startCapture(packetArrive, &data);

    // Run in an endless loop until the user presses Ctrl+C
    while(!tracker.isTerminated())
        sleep(1);

    rdr->stopCapture();

    if(!(config->quitemode)) printf("\n");

    pump::print_progressM(tracker.getTotalPacket());
    printf(" **%lu Bytes**\n", tracker.getTotalByteLen());

    // Write all stats to the specified file
    if(config->outputFileTo != "")
    {
        tracker.registerEvent();
        tracker.saveStats(config);
    }

    // Close the capture pipe
    tracker.close();
    delete rdr;
}

/* Start gathering stat info from the discovered network interface */
void doNetFIOnPcap(std::string pcapFile, struct pump::CaptureConfig* config)
{
    pump::PcapReader* rdr = pump::PcapReader::getReader(pcapFile.c_str());

    // Open the pcap file to capture from it
    if (!rdr->open())
        EXIT_WITH_CONFERROR("###ERROR : Could not open input pcap file");

    pump::Tracker tracker(init_tv);
    pump::Packet packet;

    // Run in an endless loop until the user presses Ctrl+C 
    // or the program encounters tne end of file
    while(rdr->getNextPacket(packet) && !tracker.isTerminated())
    {
        tracker.parsePacket(&packet, config);
    }

    if(!(config->quitemode)) printf("\n");

    pump::print_progressM(tracker.getTotalPacket());
    printf(" **%lu Bytes**\n", tracker.getTotalByteLen());

    // Write all stats to the specified file
    if(config->outputFileTo != "")
    {
        tracker.registerEvent();
        tracker.saveStats(config);
    }

    // Close the capture pipe
    tracker.close();
    delete rdr;
}

int main(int argc, char* argv[])
{
    gettimeofday(&init_tv, NULL);

    // Tell the user not to run as root
    if (getuid())
        EXIT_WITH_CONFERROR("###ERROR : Running NetFI requires root privileges!\n");

    // Set the initial values in the capture options
    std::string readPacketsFromPcap = "";
    std::string readPacketsFromInterface = "";
    std::string outputFileTo = "";

    int optionIndex = 0;
    uint32_t maxPacket = IN_LIMIT;
    uint32_t maxTime = IN_LIMIT;
    bool quitemode = false;
    bool mark_null = false;
    char opt = 0;

    // Set the preferences with values from command-line options 
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

    // If no input pcap file or network interface was provided - exit with error
    if (readPacketsFromPcap == "" && readPacketsFromInterface == "")
        EXIT_WITH_OPTERROR("###ERROR : Neither interface nor input pcap file were provided");

    // Should choose only one option : pcap or interface - exit with error
    if (readPacketsFromPcap != "" && readPacketsFromInterface != "")
        EXIT_WITH_OPTERROR("###ERROR : Choose only one option, pcap or interface");

    // Negative value is not allowed
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

    // Read the user's preferences file, if it exists
    // Otherwise, open a network interface to capture from it
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
    
    printf("**All Done**\n");
    WRITE_LOG("===Process Finished");
    return 0;
}