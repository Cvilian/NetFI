/* tracker.cpp
 * 
 * routines to calculate stats of each IP flow
 *  
 * NetFI - a fast and simple tool to analyze the network flow 
 */

#include <stdio.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include "utils.h"
#include "handler.h"
#include "tracker.h"
#include "layer-ip.h"
#include "layer-eth.h"
#include "layer-data.h"
#include "layer-icmp.h"

namespace pump
{
    /* Buffer to temporarily store the payload data */
    char pktBUF[maxbuf];

    /* Catch a signal (i.e., SIGINT) */
    static void onInterrupted(void* cookie)
    {
        bool* stop = (bool*)cookie;
        *stop = true;
    }

    /* Make a clean exit on interrupts */
    void stop_signal_callback_handler(int signum) 
    {
        printf("\n**All Stop**================================================\n");
        exit(signum);
    }

    /* Print a session info(IP/Port) on stdout */
    void print_progressN(Stream* ss)
    {
        char sIP[16], cIP[16];

        Flow* fwd = &ss->client;
        Flow* rev = &ss->server;

        parseIPV4(cIP, fwd->ip);
        parseIPV4(sIP, rev->ip);

        // A conversation will be displayed as follow:
        // [Clinet] ip:port <---Protocol---> ip:port [Server]
        printf("[Client] %s:%d", cIP, fwd->port);
        for (int i = strlen(cIP); i < 15; i++) printf(" ");
        uint16_t temp = fwd->port;
        for (; temp < 10000; temp *= 10) printf(" ");
        printf(" <----------");
        if(ss->proto & PROTO_UDP) printf("---UDP----");
        else if(ss->proto & PROTO_TCP) printf("---TCP----");
        else if(ss->proto & PROTO_ICMP) printf("--ICMP--");
        else if(ss->proto & PROTO_IPv4) printf("---IP---");
        else if(ss->proto & PROTO_ETHERNET) printf("Ethernet");
        else printf("Unknown-");
        printf("---------> ");
        for (int i = strlen(sIP); i < 15; i++) printf(" ");
        temp = rev->port;
        for (; temp < 10000; temp *= 10) printf(" ");
        printf("%s:%d [Server]\n", sIP, rev->port);
    }

    /*
     * Compute a hash value for a given packet
     * Packets with the same pair of source/destination IP addresses, port numbers, and protocol (5-tuples)
     * will belong to the same connection
     */
    uint32_t hashStream(pump::Packet* packet)
    {
        struct ScalarBuffer vec[5];

        uint16_t sport = 0;
        uint16_t dport = 0;
        int srcPosition = 0;

        if (packet->isTypeOf(PROTO_TCP))
        {
            pump::TcpLayer* tcpLayer = packet->getLayer<pump::TcpLayer>();
            sport = tcpLayer->getHeader()->sport;
            dport = tcpLayer->getHeader()->dport;
        }
        else
        {
            pump::UdpLayer* udpLayer = packet->getLayer<pump::UdpLayer>();
            sport = udpLayer->getHeader()->sport;
            dport = udpLayer->getHeader()->dport;
        }

        if (dport < sport)
        {
            srcPosition = 1;
        }

        vec[0 + srcPosition].buffer = (uint8_t*)&sport;
        vec[0 + srcPosition].len = 2;
        vec[1 - srcPosition].buffer = (uint8_t*)&dport;
        vec[1 - srcPosition].len = 2;

        pump::IPv4Layer* ipv4Layer = packet->getLayer<pump::IPv4Layer>();
        if (sport == dport && ipv4Layer->getHeader()->ip_dst < ipv4Layer->getHeader()->ip_src)
        {
            srcPosition = 1;
        }

        vec[2 + srcPosition].buffer = (uint8_t*)&ipv4Layer->getHeader()->ip_src;
        vec[2 + srcPosition].len = 4;
        vec[3 - srcPosition].buffer = (uint8_t*)&ipv4Layer->getHeader()->ip_dst;
        vec[3 - srcPosition].len = 4;
        vec[4].buffer = &(ipv4Layer->getHeader()->proto);
        vec[4].len = 1;

        return fnv_hash(vec, 5);
    }

    /* Check whether SYN and ACK flag is 1 and 0, respectively */
    bool isTcpSyn(pump::Packet* packet)
    {
        if (packet->isTypeOf(PROTO_TCP))
        {
            pump::TcpLayer* tcpLayer = packet->getLayer<pump::TcpLayer>();
            bool isSYN = (tcpLayer->getHeader()->flag_syn == 1);
            bool isACK = (tcpLayer->getHeader()->flag_ack == 1);
            return isSYN && !isACK;
        }

        return false;
    }

    /* Check whether the packet transmitted by a host who initiates the session */
    bool isClient(pump::Packet* packet, Stream* ss)
    {
        if(ss->client.port != ss->server.port)
        {
            if(packet->isTypeOf(PROTO_TCP))
            {
                uint16_t port = ntohs(packet->getLayer<pump::TcpLayer>()->getHeader()->sport);
                return ss->client.port == port;
            }
            else
            {
                uint16_t port = ntohs(packet->getLayer<pump::UdpLayer>()->getHeader()->sport);
                return ss->client.port == port;
            }      
        }

        uint32_t ip = packet->getLayer<IPv4Layer>()->getHeader()->ip_src;
        return ss->client.ip == ip;
    }

    /* Summarizes the packet-level stats 
     *
     * 1. Total packets
     * 2. Number of packets per second
     * 3. Number of bytes per second
     * 4. Total duration
     * 5. Maximum/Minimum/Average packet length
     * 6. Maximum/Minimum/Average inter-arrival time
     */
    void calCommon(CaptureConfig* config, FILE* f, Flow* flow, uint32_t pkt_cnt)
    {
        CommonStat* cs = &flow->st_common;

        double dur = (double)time_diff(&cs->last_tv, &cs->base_tv) / 1000000;

        if(dur == 0) dur = 0.0000001;

        // Not having a packet
        if(pkt_cnt == 0)
        {
            fprintf(f, ",0");
            for (int i = 0; i < 9; i++) fprintf(f, ",%c", config->mark_null ? '-' : '0');
            return;
        }

        fprintf(f, ",%d,%.6f,%.6f,%.6f,%d,%d,%.3f",
            pkt_cnt, (double)cs->pkt_cnt/dur, (double)cs->pktlen.s/dur, dur,
            cs->pktlen.M, cs->pktlen.m, (double)cs->pktlen.s/pkt_cnt);
        
        // If total packet count is less than 2, it can not compute the inter-arrival time
        if(pkt_cnt < 2)
        {
            for (int i = 0; i < 3; i++) fprintf(f, ",%c", config->mark_null ? '-' : '0');
            return;
        }

        fprintf(f, ",%.6f,%.6f,%.6f",
            time_raws(&cs->intarr_time.M), time_raws(&cs->intarr_time.m), time_raws(&cs->intarr_time.s)/(pkt_cnt-1));
    } 

    /* Summarizes the Ethernet-layer-level stats 
     *
     * 1. Ratio of packets with ethernet padding
     * 2. Maximum/Minimum/Average ethernet padding size
     */
    void calEth(CaptureConfig* config, FILE* f, Flow* flow, uint32_t pkt_cnt)
    {
        EthStat* es = &flow->st_eth;

        // None of the datagrams correspond to Ethernet packet
        if(pkt_cnt == 0)
        {
            for (int i = 0; i < 4; i++) fprintf(f, ",%c", config->mark_null ? '-' : '0');
            return;
        }

        // There were no packets having a ethernet padding
        if(es->pad_cnt == 0)
        {
            fprintf(f, ",0");
            for (int i = 0; i < 3; i++) fprintf(f, ",%c", config->mark_null ? '-' : '0');
            return;
        } 

        fprintf(f, ",%.3f,%d,%d,%.3f",
            (double)es->pad_cnt/pkt_cnt, es->padlen.M, es->padlen.m, (double)es->padlen.s/pkt_cnt);
    }

    /* Summarizes the IPv4-layer-level stats 
     *
     * 1. Differentiated Service Codepoint (Dscp)
     * 2. Ratio of packets with DF (Don't Fragement) bit
     * 3. Ratio of packets with MF (More Fragement) bit
     * 4. Maximum/Minimum/Average Time to Live (TTL)
     * 5. Ratio of packets without supporting ECN
     * 6. Ratio of packets with supporting ECT0
     * 7. Ratio of packets with supporting ECT1
     * 8. Ratio of packets with supporting CE
     * 9. Maximum/Minimum/Average Fragment offset without MF bit
     */
    void calIPv4(CaptureConfig* config, FILE* f, Flow* flow, uint32_t pkt_cnt)
    {
        IPv4Stat* is = &flow->st_ip;

        // None of the datagrams correspond to IPv4 packet
        if(pkt_cnt == 0)
        {
            for (int i = 0; i < 13; i++) fprintf(f, ",%c", config->mark_null ? '-' : '0');
            return;
        }

        fprintf(f, ",%s", dscp_type.find(is->dscp) == dscp_type.end() ? "Unknown" : dscp_type.at(is->dscp).c_str());

        fprintf(f, ",%.3f,%.3f,%d,%d,%.3f,%.3f,%.3f,%.3f,%.3f",
            (double)is->df_cnt/pkt_cnt, (double)is->mf_cnt/pkt_cnt,
            is->ttl.M, is->ttl.m, (double)is->ttl.s/pkt_cnt,
            (double)is->ecn_none_cnt/pkt_cnt, (double)is->ecn_ect0_cnt/pkt_cnt,
            (double)is->ecn_ect1_cnt/pkt_cnt, (double)is->ecn_ce_cnt/pkt_cnt);

        // Load the info about last seen fragment offset
        if(flow->last_fragoff > 0)
        {
            is->fragoff_cnt++;
            update_ns<uint16_t>(&is->fragoff, flow->last_fragoff);
        }
        
        // There were no packets having a fragment offset
        if(is->fragoff_cnt == 0)
        {
            for (int i = 0; i < 3; i++) fprintf(f, ",%c", config->mark_null ? '-' : '0');
            return;
        }

        fprintf(f, ",%d,%d,%.3f",
            is->fragoff.M, is->fragoff.m, (is->fragoff_cnt == 0 ? 0 : (double)is->fragoff.s/is->fragoff_cnt));
    }

    /* Summarizes the ICMP-layer-level stats 
     *
     * 1.  Ratio of packets with ICMP frame
     * 2.  Ratio of packets with 'Echo Reply' message
     * 3.  Ratio of packets with 'Echo Request' message
     * 4.  Ratio of packets with 'Network Unreachable' message
     * 5.  Ratio of packets with 'Host Unreachable' message
     * 6.  Ratio of packets with 'Protocol Unreachable' message
     * 7.  Ratio of packets with 'Port Unreachable' message
     * 8.  Ratio of packets with 'Destination Host Prohibited' message
     * 9.  Ratio of packets with 'Communication Prohibited' message
     * 10. Ratio of packets with 'Time exceeded' message
     */
    void calIcmp(CaptureConfig* config, FILE* f, Flow* flow, uint32_t pkt_cnt)
    {
        IcmpStat* ms = &flow->st_icmp;

        // None of the datagrams correspond to ICMP packet
        if(pkt_cnt == 0)
        {
            for (int i = 0; i < 10; i++) fprintf(f, ",%c", config->mark_null ? '-' : '0');
            return;
        }

        fprintf(f, ",%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f",
            (double)ms->icmp_cnt/pkt_cnt, (double)ms->echo_reply/pkt_cnt,
            (double)ms->echo_request/pkt_cnt, (double)ms->net_unreachable/pkt_cnt,
            (double)ms->host_unreachable/pkt_cnt, (double)ms->proto_unreachable/pkt_cnt,
            (double)ms->port_unreachable/pkt_cnt, (double)ms->host_prohibited/pkt_cnt,
            (double)ms->comm_prohibited/pkt_cnt, (double)ms->time_exceeded/pkt_cnt);
    }


    /* Summarizes the Transport-layer-level(both TCP and UDP) stats 
     *
     * 1. Ratio of packets with TCP/UDP payload
     * 2. Maximum/Minimum/Average TCP/UDP payload length
     */
    void calTransport(CaptureConfig* config, FILE* f, Flow* flow, uint32_t pkt_cnt)
    {
        TransportStat* tps = &flow->st_trans;

        // None of the datagrams correspond to Transport layer packet
        if(pkt_cnt == 0)
        {
            for (int i = 0; i < 4; i++) fprintf(f, ",%c", config->mark_null ? '-' : '0');
            return;
        }

        // Check whether at least one packet has payload
        if(tps->has_pay == 0)
        {
            fprintf(f, ",0");
            for (int i = 0; i < 3; i++) fprintf(f, ",%c", config->mark_null ? '-' : '0');
        }
        else
        {
            fprintf(f, ",%.3f,%d,%d,%.3f",
                (double)tps->has_pay/pkt_cnt, tps->paylen.M, tps->paylen.m, (double)tps->paylen.s/tps->has_pay);
        }
    }

    /* Summarizes the TCP-layer-level stats 
     *
     * 1.  Ratio of packets with ACK to a previous segment
     * 2.  Maximum/Minimum/Average number of frame acked at once
     * 3.  Maximum/Minimum/Average number of segment splits
     * 4.  Maximum/Minimum/Average Round Trip TIme (RTT) to ACK
     * 5.  Ratio of packets with nonzero ack while ACK flag is not set
     * 6.  Ratio of acked lost packets
     * 7.  Ratio of packets with bytes in flight
     * 8.  Maximum/Minimum/Average bytes in flight
     * 9.  Ratio of packets with duplicated ack
     * 10. Ratio of fast-retransmission
     * 11. Ratio of keep-alive
     * 12. Ratio of keep-alive ACK
     * 13. Ratio of packets missed some previous segments
     * 14. Ratio of out-of-order segments
     * 15. Ratio of packet sent bytes since last PSH flag
     * 16. Maximum/Minimum/Average push bytes right before occurence of PSH flag
     * 17. Ratio of retransmission
     * 18. Maximum/Minimum/Average retransmission time-out
     * 19. Ratio of spurious retransmission
     * 20. Ratio of packets with full window
     * 21. Ratio of packets with TCP window update
     * 22. Ratio of packets with zero window
     * 23. Ratio of zero-window-probe
     * 24. Ratio of zero-window-probe ACK
     * 25. Ratio of FIN/SYN/RST/PSH/ACK/URG/ECE/CWR flags
     * 26. Ratio of packets with TCP options
     * 27. Maximum/Minimum/Average TCP option length
     * 28. Maximum/Minimum/Average number of TCP option
     * 29. Ratio of packets with Selective ACK (SACK)
     * 30. Ratio of packets with timestamp
     * 31. Ratio of packets with TCP Fast Open (TFO)
     * 32. Ratio of packets with multipath TCP frame
     * 33. TCP window scalier
     * 34. Maximum segment size
     * 35. SACK permitted value
     * 36. Maximum/Minimum/Average TCP window
     * 37. Initial Round Trip Time
     */
    void calTcp(CaptureConfig* config, FILE* f, Flow* flow, uint32_t pkt_cnt)
    {
        TcpStat* ts = &flow->st_tcp;

        // None of the datagrams correspond to TCP packet
        if (pkt_cnt == 0)
        {
            for (int i = 0; i < 61; i++) fprintf(f, ",%c", config->mark_null ? '-' : '0');
            return;
        }

        // Check whether at least one packet was acknowledged
        if (ts->a_ack_frame_cnt == 0)
        {
            fprintf(f, ",0");
            for (int i = 0; i < 9; i++) fprintf(f, ",%c", config->mark_null ? '-' : '0');
        }
        else
        {
            fprintf(f, ",%.3f,%d,%d,%.3f,%d,%d,%.3f,%.6f,%.6f,%.6f",
                (double)ts->a_ack_frame_cnt/pkt_cnt,
                ts->acked_frame_cnt.M, ts->acked_frame_cnt.m, (double)ts->acked_frame_cnt.s/ts->a_ack_frame_cnt,
                ts->seg_frame_cnt.M, ts->seg_frame_cnt.m, (double)ts->seg_frame_cnt.s/ts->a_ack_frame_cnt,
                time_raws(&ts->ack_rtt.M), time_raws(&ts->ack_rtt.m), time_raws(&ts->ack_rtt.s)/ts->a_ack_frame_cnt);
        }

        fprintf(f, ",%.3f,%.3f",
            (double)ts->a_ack_none/pkt_cnt, (double)ts->a_acked_unseen/pkt_cnt);

        // Check whether there exists a byte in flight
        if (ts->a_bif_cnt == 0)
        {
            fprintf(f, ",0");
            for (int i = 0; i < 3; i++) fprintf(f, ",%c", config->mark_null ? '-' : '0');
        }
        else
        {
            fprintf(f, ",%.3f,%d,%d,%.3f",
                (double)ts->a_bif_cnt/pkt_cnt,
                ts->bif.M, ts->bif.m, (double)ts->bif.s/ts->a_bif_cnt);
        }

        fprintf(f, ",%.3f,%.3f,%.3f,%.3f,%.3f,%.3f",
            (double)ts->a_dup_ack/pkt_cnt, (double)ts->a_fast_retrans/pkt_cnt,
            (double)ts->a_keep_alive/pkt_cnt, (double)ts->a_keep_alive_ack/pkt_cnt,
            (double)ts->a_lost_segment/pkt_cnt, (double)ts->a_out_of_order/pkt_cnt);

        if(flow->push_bytes > 0)
        {
            ts->a_push_cnt++;
            update_ns<uint32_t>(&ts->push_bytes, flow->push_bytes);
        }

        if (ts->a_push_cnt == 0)
        {
            fprintf(f, ",0");
            for (int i = 0; i < 3; i++) fprintf(f, ",%c", config->mark_null ? '-' : '0');
        }
        else
        {
            fprintf(f, ",%.3f,%d,%d,%.3f",
                (double)ts->a_push_cnt/pkt_cnt,
                ts->push_bytes.M, ts->push_bytes.m, (double)ts->push_bytes.s/ts->a_push_cnt);
        }

        // Check whether there exists a retransmission
        if(ts->a_retrans == 0)
        {
            fprintf(f, ",0");
            for (int i = 0; i < 3; i++) fprintf(f, ",%c", config->mark_null ? '-' : '0');
        }
        else
        {
            fprintf(f, ",%.3f,%.6f,%.6f,%.6f",
                (double)ts->a_retrans/pkt_cnt, time_raws(&ts->rto.M), 
                time_raws(&ts->rto.m), time_raws(&ts->rto.s)/ts->a_retrans);
        }

        fprintf(f, ",%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f",
            (double)ts->a_spur_retrans/pkt_cnt, (double)ts->a_window_full/pkt_cnt,
            (double)ts->a_window_update/pkt_cnt, (double)ts->a_zero_window/pkt_cnt,
            (double)ts->a_zero_window_probe/pkt_cnt, (double)ts->a_zero_window_probe_ack/pkt_cnt,
            (double)ts->f_ack/pkt_cnt, (double)ts->f_cwr/pkt_cnt, (double)ts->f_ece/pkt_cnt,
            (double)ts->f_fin/pkt_cnt, (double)ts->f_psh/pkt_cnt, (double)ts->f_rst/pkt_cnt,
            (double)ts->f_syn/pkt_cnt, (double)ts->f_urg/pkt_cnt);

        // Check whether at least one packet has its TCP option field
        if(ts->has_opt == 0)
        {
            fprintf(f, ",0");
            for (int i = 0; i < 10; i++) fprintf(f, ",%c", config->mark_null ? '-' : '0');
        }
        else
        {
            fprintf(f, ",%.3f,%d,%d,%.3f,%d,%d,%.3f,%.3f,%.3f,%.3f,%.3f",
                (double)ts->has_opt/pkt_cnt,
                ts->optlen.M, ts->optlen.m, (double)ts->optlen.s/ts->has_opt,
                ts->optcnt.M, ts->optcnt.m, (double)ts->optcnt.s/ts->has_opt,
                (double)ts->opt_sack_cnt/ts->has_opt, (double)ts->opt_timestamp_cnt/ts->has_opt,
                (double)ts->opt_tfo_cnt/ts->has_opt, (double)ts->opt_mptcp_cnt/ts->has_opt);
        }

        if(ts->opt_win_scale == -1) fprintf(f, ",%c", config->mark_null ? '-' : '0');
        else fprintf(f, ",%d", ts->opt_win_scale);

        if(ts->opt_mss == -1) fprintf(f, ",%c", config->mark_null ? '-' : '0');
        else fprintf(f, ",%d", ts->opt_mss);

        if(ts->opt_sack_perm == -1) fprintf(f, ",%c", config->mark_null ? '-' : '0');
        else fprintf(f, ",%d", ts->opt_sack_perm);

        fprintf(f, ",%d,%d,%.3f",
            ts->win.M, ts->win.m, (double)ts->win.s/pkt_cnt);
    }

    // Extract the Packet-level stats 
    void parseCommon(pump::Packet* packet, Flow* fwd, Flow* rev)
    {
        timeval ref_tv = packet->getTimeStamp();

        // Store the initial packet's timestamp for the calculation of inter-arrival time
        if(time_isZero(&fwd->st_common.base_tv)
        || time_diff(&ref_tv, &fwd->st_common.base_tv) < 0)
        {
            time_update(&fwd->st_common.base_tv, &ref_tv);
        }

        if(fwd->st_common.pkt_cnt++ > 0)
        {
            // Inter-arrival time
            timeval delta_tv;
            time_delta(&delta_tv, &ref_tv, &fwd->st_common.last_tv);
            update_ts(&fwd->st_common.intarr_time, &delta_tv);
        }

        time_update(&fwd->st_common.last_tv, &ref_tv);

        uint16_t pk_len = packet->getDataLen();
        update_ns<uint16_t>(&fwd->st_common.pktlen, pk_len);
    }

    // Extract the Ethernet-layer-level stats 
    void parseEth(pump::Packet* packet, Flow* fwd, Flow* rev)
    {
        if(!(packet->getProtocolTypes() & PROTO_TRAILER)) return;

        fwd->st_eth.pad_cnt++;

        uint16_t padlen = (uint16_t)packet->getLayer<pump::TrailerLayer>()->getHeaderLen();
        update_ns<uint16_t>(&(fwd->st_eth.padlen), padlen);
    }

    // Extract the IPv4-layer-level stats 
    void parseIPv4(pump::Packet* packet, Flow* fwd, Flow* rev)
    {
        fwd->st_ip.dscp = packet->getLayer<pump::IPv4Layer>()->getHeader()->dscp;

        uint8_t ecn = packet->getLayer<pump::IPv4Layer>()->getHeader()->ecn;

        // Explicit Congestion Notification (ECN)
        switch (ecn)
        {
            case ETHERECN_ECT0:
                fwd->st_ip.ecn_ect0_cnt++;
                break;
            case ETHERECN_ECT1:
                fwd->st_ip.ecn_ect1_cnt++;
                break;
            case ETHERECN_CE:
                fwd->st_ip.ecn_ce_cnt++;
                break;
            default:
                fwd->st_ip.ecn_none_cnt++;
                break;
        }

        uint8_t flags = packet->getLayer<pump::IPv4Layer>()->getFragmentFlags();

        if(flags & 0x40) fwd->st_ip.df_cnt++;
        if(flags & 0x20) fwd->st_ip.mf_cnt++;

        fwd->last_fragoff = packet->getLayer<pump::IPv4Layer>()->getFragmentOffset();

        if(!(flags & 0x20) && fwd->last_fragoff)
        { 
            update_ns<uint16_t>(&(fwd->st_ip.fragoff), fwd->last_fragoff);
            fwd->st_ip.fragoff_cnt++;
        }

        uint8_t ttl = packet->getLayer<pump::IPv4Layer>()->getHeader()->ttl;
        update_ns<uint8_t>(&(fwd->st_ip.ttl), ttl);
    }

    // Extract the ICMP-layer-level stats 
    void parseIcmp(pump::Packet* packet, Flow* fwd, Flow* rev)
    {
        fwd->st_icmp.icmp_cnt++;
        uint8_t type = packet->getLayer<pump::IcmpLayer>()->getMessageType();
        uint8_t code = packet->getLayer<pump::IcmpLayer>()->getMessageCode();

        // ICMP message type
        switch (type)
        {
            case ICMP_ECHO_REPLY:
                fwd->st_icmp.echo_reply++;
                break;
            case ICMP_DEST_UNREACHABLE:
                switch (code)
                {
                    case ICMP_NET_UNREACHABLE :
                        fwd->st_icmp.net_unreachable++;
                        break;
                    case ICMP_HOST_UNREACHABLE :
                        fwd->st_icmp.host_unreachable++;
                        break;
                    case ICMP_PROTO_UNREACHABLE :
                        fwd->st_icmp.proto_unreachable++;
                        break;
                    case ICMP_PORT_UNREACHABLE :
                        fwd->st_icmp.port_unreachable++;
                        break;
                    case ICMP_DEST_HOST_PROHIBITED :
                        fwd->st_icmp.host_prohibited++;
                        break;
                    case ICMP_COMMUNICATION_PROHIBITED :
                        fwd->st_icmp.comm_prohibited++;
                        break;
                    default:
                        break;
                }
                break;
            case ICMP_ECHO_REQUEST:
                fwd->st_icmp.echo_request++;
                break;
            case ICMP_TIME_EXCEEDED:
                fwd->st_icmp.time_exceeded++;
                break;     
            default:
                break;
        }
    }

    // Extract the TCP-layer-level stats 
    void parseTcp(pump::Packet* packet, Stream* ss, Flow* fwd, Flow* rev)
    {
        timeval ref_tv = packet->getTimeStamp();

        bool isACK = (packet->getLayer<pump::TcpLayer>()->getHeader()->flag_ack == 1);
        bool isCWR = (packet->getLayer<pump::TcpLayer>()->getHeader()->flag_cwr == 1);
        bool isECE = (packet->getLayer<pump::TcpLayer>()->getHeader()->flag_ece == 1);
        bool isFIN = (packet->getLayer<pump::TcpLayer>()->getHeader()->flag_fin == 1);
        bool isPSH = (packet->getLayer<pump::TcpLayer>()->getHeader()->flag_psh == 1);
        bool isRST = (packet->getLayer<pump::TcpLayer>()->getHeader()->flag_rst == 1);
        bool isSYN = (packet->getLayer<pump::TcpLayer>()->getHeader()->flag_syn == 1);
        bool isURG = (packet->getLayer<pump::TcpLayer>()->getHeader()->flag_urg == 1);

        fwd->st_tcp.f_ack += isACK;
        fwd->st_tcp.f_cwr += isCWR;
        fwd->st_tcp.f_ece += isECE;
        fwd->st_tcp.f_fin += isFIN;
        fwd->st_tcp.f_psh += isPSH;
        fwd->st_tcp.f_rst += isRST;
        fwd->st_tcp.f_syn += isSYN;
        fwd->st_tcp.f_urg += isURG;

        uint32_t seq = ntohl(packet->getLayer<pump::TcpLayer>()->getHeader()->rawseq);
        uint32_t ack = ntohl(packet->getLayer<pump::TcpLayer>()->getHeader()->rawack);
        uint16_t win = packet->getLayer<pump::TcpLayer>()->getHeader()->rawwin;

        size_t seglen = packet->getLayer<pump::TcpLayer>()->getLayerPayloadSize();

        size_t optlen = packet->getLayer<pump::TcpLayer>()->getOptionLen();

        // TCP options
        if(optlen)
        {
            uint8_t optcnt = packet->getLayer<pump::TcpLayer>()->getOptionCount();
            update_ns<uint8_t>(&(fwd->st_tcp.optcnt), optcnt);
            uint8_t* wscale = packet->getLayer<pump::TcpLayer>()->getOption(TCPOPT_WINSCALE);

            if(wscale != 0)
            {
                fwd->win_scale = *(wscale + 2);
                fwd->st_tcp.opt_win_scale = fwd->win_scale;
            }
            
            uint8_t* mss = packet->getLayer<pump::TcpLayer>()->getOption(TCPOPT_MSS);
            if(mss != 0)
            {
                fwd->st_tcp.opt_mss = 256*(*(mss + 2)) + *(mss + 3);
            }

            if(packet->getLayer<pump::TcpLayer>()->getOption(TCPOPT_SACK_PERM) != 0)
            {
                fwd->st_tcp.opt_sack_perm++;
            }

            if(packet->getLayer<pump::TcpLayer>()->getOption(TCPOPT_SACK) != 0)
            {
                fwd->st_tcp.opt_sack_cnt++;
            }

            if(packet->getLayer<pump::TcpLayer>()->getOption(TCPOPT_TIMESTAMP) != 0)
            {
                fwd->st_tcp.opt_timestamp_cnt++;
            }

            if(packet->getLayer<pump::TcpLayer>()->getOption(TCPOPT_FASTCOOKIE) != 0)
            {
                fwd->st_tcp.opt_tfo_cnt++;
            }

            if(packet->getLayer<pump::TcpLayer>()->getOption(TCPOPT_MPTCP) != 0)
            {
                fwd->st_tcp.opt_mptcp_cnt++;
            }

            fwd->st_tcp.has_opt++;
            update_ns<uint8_t>(&fwd->st_tcp.optlen, optlen);
        }

        // If this is the first packet for this direction,
        // we need to store the base sequence number
        // This enables us to calculate the relative seq/ack numbers,
        // which is helpful for the advanced analysis of the given segment
        if (!(fwd->flags & F_BASE_SEQ_SET))
        {
            fwd->baseseq = seq;
            fwd->flags |= F_BASE_SEQ_SET;
        }

        // Compute the relative seq/ack numbers
        seq -= fwd->baseseq;
        ack -= rev->baseseq;

        if (isACK)
        {
            rev->valid_bif = true;
        }

        // Set 'ACK Non-Zero' when
        // (1) ACK is set
        // (2) ack number is not zero
        if(isACK && ack > 0) fwd->st_tcp.a_ack_none++;

        fwd->a_flags = 0;

        // Set 'ZERO WINDOW PROBE' when
        // (1) segment size is one 
        // (2) sequence number is equal to the next expected sequence number
        // (3) last seen window size in the reverse direction was zero 
        if (seglen == 1
        && seq == fwd->nextseq
        && rev->win == 0)
        {
            fwd->a_flags |= TCP_A_ZERO_WINDOW_PROBE;
            fwd->st_tcp.a_zero_window_probe++;
            goto retrans_check;
        }

        // Set 'ZERO WINDOW' when
        // (1) window size is zero
        // (2) none of SYN, FIN, and RST or set
        if (win == 0
        && (!(isRST || isFIN || isSYN)))
        {
            fwd->a_flags |= TCP_A_ZERO_WINDOW;
            fwd->st_tcp.a_zero_window++;
        }

        //  Set 'LOST SEGMENT' when
        // (1) current sequence number is greater than the next expected sequence number
        // (2) RST is not set
        if (fwd->nextseq
        && seq > fwd->nextseq
        && !isRST)
        {
            fwd->a_flags |= TCP_A_LOST_PACKET;
            fwd->st_tcp.a_lost_segment++;
            fwd->valid_bif = false;
        }

        // Set 'KEEP ALIVE' when
        // (1) segment size is zero or one 
        // (2) sequence number is one byte less than the next expected sequence number
        // (3) none of SYN, FIN, or RST are set
        if (seglen <= 1
        && !(isFIN || isSYN || isRST)
        && fwd->nextseq - 1 == seq)
        {
            fwd->a_flags |= TCP_A_KEEP_ALIVE;
            fwd->st_tcp.a_keep_alive++;
        }

        // Set 'WINDOW UPDATE' when
        // (1) segment size is zero
        // (2) window size is non-zero and not equal to the last seen window size
        // (3) sequence number is equal to the next expected sequence number
        // (4) none of SYN, FIN, or RST are set
        if (seglen == 0
        && win
        && win != fwd->win
        && seq == fwd->nextseq
        && ack == fwd->lastack
        && !(isSYN || isFIN || isRST)) 
        {
            fwd->a_flags |= TCP_A_WINDOW_UPDATE;
            fwd->st_tcp.a_window_update++;
        }

        // Set 'WINDOW FULL' when
        // (1) segment size is non-zero
        // (2) saw the window size in the reverse direction
        // (3) segment size exceeds the window size in the reverse direction
        // (4) none of SYN, FIN, or RST are set
        if (seglen > 0
        && rev->win_scale != -1
        && seq + seglen == (rev->lastack + (rev->win << (rev->win_scale == -2 ? 0 : rev->win_scale)))
        && !(isSYN || isFIN || isRST))
        {
            fwd->a_flags |= TCP_A_WINDOW_FULL;
            fwd->st_tcp.a_window_full++;
        }

        // Set 'KEEP ALIVE ACK' when
        // (1) segment size is zero
        // (2) window size is non-zero and hasn’t changed
        // (3) current sequence number is the same as the next expected sequence number
        // (4) current acknowledgement number is the same as the last-seen acknowledgement number
        // (5) most recently seen packet in the reverse direction was a keepalive
        // (6) none of SYN, FIN, or RST are set
        if (seglen==0
        && win
        && win == fwd->win
        && seq == fwd->nextseq
        && ack == fwd->lastack
        && (rev->a_flags & TCP_A_KEEP_ALIVE)
        && !(isSYN || isFIN || isRST)) 
        {
            fwd->a_flags |= TCP_A_KEEP_ALIVE_ACK;
            fwd->st_tcp.a_keep_alive_ack++;
            goto retrans_check;
        }

        // Set 'ZERO WINDOW PROBE ACK' when
        // (1) segment size is zero
        // (2) window size is zero
        // (3) current sequence number is the same as the next expected sequence number
        // (4) current acknowledgement number is the same as the last-seen acknowledgement number
        // (5) most recently seen packet in the reverse direction was a zero window probe
        // (6) none of SYN, FIN, or RST are set
        if(seglen == 0
        && win == 0
        && win == fwd->win
        && seq == fwd->nextseq
        && ack == fwd->lastack
        && (rev->a_flags & TCP_A_ZERO_WINDOW_PROBE)
        && !(isSYN || isFIN || isRST)) 
        {
            fwd->a_flags |= TCP_A_ZERO_WINDOW_PROBE_ACK;
            fwd->st_tcp.a_zero_window_probe_ack++;
            goto retrans_check;
        }

        // Set 'DUPLICATE ACK' when
        // (1) segment size is zero
        // (2) window size is non-zero and hasn’t changed
        // (3) current sequence number is the same as the next expected sequence number
        // (4) current acknowledgement number is the same as the last-seen acknowledgement number
        // (5) none of SYN, FIN, or RST are set
        if (seglen==0
        && win
        && win == fwd->win
        && seq == fwd->nextseq
        && ack == fwd->lastack
        && !(isSYN || isFIN || isRST)) 
        {
            fwd->a_flags |= TCP_A_DUPLICATE_ACK;
            fwd->st_tcp.a_dup_ack++;
            fwd->dup_ack_cnt++;
        }

        retrans_check:

        if (ack != fwd->lastack ) 
        {
            fwd->dup_ack_cnt = 0;
        }

        // Set 'ACKED UNSEEN' when
        // (1) the expected next acknowledgement number is set for the reverse direction
        // (2) current acknowledgement number is tlarger the last-seen acknowledgement number
        // (3) ACK is set
        if (rev->max_seq_acked
        && ack > rev->max_seq_acked
        && isACK) 
        {
            fwd->a_flags |= TCP_A_ACK_LOST_PACKET;
            rev->max_seq_acked = rev->nextseq;
            fwd->st_tcp.a_acked_unseen++;
        }

        // Set one of the 'RETRANSMISSION'/'FAST RETRANSMISSION'/'OUT OF ORDER' when
        // (1) segment size is non-zero or the SYN or FIN is set
        // (2) not a keepalive packet
        if ((seglen > 0 || isSYN || isFIN)
        && !(fwd->a_flags & TCP_A_KEEP_ALIVE))
        {
            bool seq_not_advanced = fwd->nextseq 
                                    && (seq < fwd->nextseq) 
                                    && !(seglen > 1 && fwd->nextseq - 1 == seq);

            int64_t t = time_raw(&rev->lastack_time);

            // Set 'FAST RETRANSMISSION' when
            // (1) next expected sequence number is greater than the current sequence number
            // (2) segment size is less than 2
            //     or the next expected sequence number is not equal to the current sequence number
            // (3) at least two duplicate ACKs in the reverse direction
            // (4) current sequence number equals the next expected acknowledgement number
            // (5) saw the last acknowledgement less than 20ms ago
            if (seq_not_advanced
            && rev->dup_ack_cnt >= 2
            && rev->lastack == seq
            && t < 20000 ) 
            {
                fwd->a_flags |= TCP_A_FAST_RETRANSMISSION;
                fwd->st_tcp.a_fast_retrans++;
                goto seq_update;
            }

            int64_t ooo_thres = time_isZero(&ss->init_rtt) ? 3000 : time_raw(&ss->init_rtt);
            t = time_raw(&fwd->nextseq_time);

            // Set 'OUT OF ORDER' when
            // (1) next expected sequence number is greater than the current sequence number
            // (2) segment size is less than 2
            //     or the next expected sequence number is not equal to the current sequence number
            // (3) last segment arrived within the Out-Of-Order RTT threshold
            //     (threshold is either the initial RTT if it is present, or the default value of 3ms)
            // (4) next expected sequence number and the next sequence number differ
            if (seq_not_advanced
            && t < ooo_thres
            && fwd->nextseq != seq + seglen )
            {
                fwd->a_flags |= TCP_A_OUT_OF_ORDER;
                fwd->st_tcp.a_out_of_order++;
                goto seq_update;
            }

            // Set 'SPURIOUS RETRANSMISSION' when
            // (1) segment length is greater than zero
            // (2) last-seen acknowledgement number has been set
            // (3) next sequence number is less than or equal to the last-seen acknowledgement number
            if (seglen > 0
            && rev->lastack
            && seq + seglen <= rev->lastack)
            {
                fwd->a_flags |= TCP_A_SPURIOUS_RETRANSMISSION;
                fwd->st_tcp.a_spur_retrans++;
                goto seq_update;
            }

            // Set a geberic 'RETRANSMISSION' when
            // (1) next expected sequence number is greater than the current sequence number
            // (2) segment size is less than 2
            //     or the next expected sequence number is not equal to the current sequence number
            if (seq_not_advanced) 
            {
                fwd->a_flags |= TCP_A_RETRANSMISSION;
                fwd->st_tcp.a_retrans++;
                time_delta(&fwd->rto_tv, &ref_tv, &fwd->nextseq_time);
                update_ts(&fwd->st_tcp.rto, &fwd->rto_tv);
            }
        }

        seq_update:

        // next sequence number is seglen bytes away, plus SYN/FIN which counts as one byte
        uint32_t nextseq = seq + seglen;

        tcp_unacked *ual = NULL;

        if ((seglen || isSYN || isFIN))
        {
            // Store the unacknowledged segments temporarily
            // It will be utilized when we count the number of ACKED packets later
            ual = (tcp_unacked*)malloc(sizeof(tcp_unacked));
            ual->next = fwd->lastseg;
            fwd->lastseg = ual;
            fwd->seg_idx++;
            ual->seq = seq;
            ual->tv = packet->getTimeStamp();

            if(isSYN || isFIN) 
            {
                nextseq+=1;
            }
            else
            {
                fwd->st_trans.has_pay++;
                update_ns<uint16_t>(&fwd->st_trans.paylen, seglen);
            }

            ual->nextseq = nextseq;
        }

        // Store the highest number seen so far for nextseq so we can detect
        // when we receive segments that arrive with a "hole"
        // If we don't have anything since before, just store what we got
        // ZERO WINDOW PROBEs are special and don't really advance the next sequence number
        if ((nextseq > fwd->nextseq || !fwd->nextseq) 
        && !(fwd->a_flags & TCP_A_ZERO_WINDOW_PROBE))
        {
            fwd->nextseq = nextseq;
            time_update(&fwd->nextseq_time, &ref_tv);   
        }

        // Store the highest sequence number temporarily
        // It will be beneficial for finding 'ACKED UNSEEN' packets
        if((seq == fwd->max_seq_acked || !fwd->max_seq_acked)
        && !(fwd->a_flags & TCP_A_ZERO_WINDOW_PROBE)) 
        {
            fwd->max_seq_acked = nextseq;
        }

        fwd->win = win;
        fwd->lastack = ack;
        update_ns<uint32_t>(&fwd->st_tcp.win, win);
        time_update(&(fwd->lastack_time), &ref_tv);

        uint32_t ack_cnt=0;
        tcp_unacked *prevual = NULL;

        // Check the acknowledged segments
        ual = rev->lastseg;

        while (ual)
        {
            tcp_unacked *tmpual;

            // If this ack matches the segment, process accordingly
            if (ack == ual->nextseq)
            {
                timeval delta_tv;
                time_delta(&delta_tv, &ref_tv, &ual->tv);
                update_ts(&rev->st_tcp.ack_rtt, &delta_tv);
                rev->st_tcp.a_ack_frame_cnt++;
            }
            // If this acknowledges part of the segment, adjust the segment info for the acked part
            else if (ack > ual->seq && ack <= ual->nextseq)
            {
                ual->seq = ack;
                continue;
            }
            // If this acknowledges a segment prior to this one, leave this segment alone and move on
            else if (ual->nextseq > ack)
            {
                prevual = ual;
                ual = ual->next;
                continue;
            }

            // This segment is old, or an exact match.  Delete the segment from the list
            ack_cnt++;
            tmpual = ual->next;

            if (!prevual)
            {
                rev->lastseg = tmpual;
            }
            else
            {
                prevual->next = tmpual;
            }

            free(ual);
            ual = tmpual;
            rev->seg_idx--;
        }

        if(ack_cnt > 0)
        {
            update_ns<uint32_t>(&rev->st_tcp.acked_frame_cnt, ack_cnt);
            update_ns<uint32_t>(&rev->st_tcp.seg_frame_cnt, ack_cnt+rev->seg_idx);
        }

        // Check how many bytes of data are there in flight after this frame was sent
        ual = fwd->lastseg;

        if (seglen != 0 
        && ual 
        && fwd->valid_bif)
        {
            uint32_t first_seq, last_seq, in_flight;

            first_seq = ual->seq - fwd->baseseq;
            last_seq = ual->nextseq - fwd->baseseq;

            while (ual)
            {
                if (ual->nextseq - fwd->baseseq > last_seq)
                {
                    last_seq = ual->nextseq - fwd->baseseq;
                }

                if (ual->seq - fwd->baseseq < first_seq) 
                {
                    first_seq = ual->seq - fwd->baseseq;
                }

                ual = ual->next;
            }
            in_flight = last_seq - first_seq;

            if (in_flight > 0 && in_flight < 2000000000)
            {
                uint32_t bytes_in_flight = in_flight;

                if (isSYN || isFIN)
                {
                    bytes_in_flight -= 1;
                }

                update_ns<uint32_t>(&fwd->st_tcp.bif, bytes_in_flight);
                fwd->st_tcp.a_bif_cnt++;
            }

            if(isPSH)
            {
                if(fwd->push_set_last)
                {
                    update_ns<uint32_t>(&fwd->st_tcp.push_bytes, fwd->push_bytes);
                    fwd->st_tcp.a_push_cnt++;
                    fwd->push_bytes = seglen;
                }
                else
                {
                    fwd->push_bytes += seglen;
                }

                fwd->push_set_last = true;
            }
            else if (fwd->push_set_last)
            {
                update_ns<uint32_t>(&fwd->st_tcp.push_bytes, fwd->push_bytes);
                fwd->st_tcp.a_push_cnt++;
                fwd->push_bytes = seglen;
                fwd->push_set_last = false;
            }
            else
            {
                fwd->push_bytes += seglen;
            }
        }

        // Initial RTT
        if(!isSYN 
        && isACK
        && !time_isZero(&(ss->last_syn))
        && time_isZero(&(ss->init_rtt))){
            time_delta(&(ss->init_rtt), &ref_tv, &(ss->last_syn));
        }

        // Re-calculate window size, based on scaling factor
        if(isSYN)
        {
            if(fwd->win_scale == -1)
            {
                fwd->win_scale = -2;
                rev->win_scale = -2;
            }
            else if(isACK && rev->win_scale == -2)
            {
                fwd->win_scale = -2;
            }
        }
    }

    // Extract the UDP-layer-level stats 
    void parseUdp(pump::Packet* packet, Flow* fwd, Flow* rev)
    {
        size_t seglen = packet->getLayer<pump::UdpLayer>()->getLayerPayloadSize();

        if(seglen > 0)
        {
            fwd->st_trans.has_pay++;
            update_ns<uint16_t>(&fwd->st_trans.paylen, seglen);
        }
    }

    Tracker::Tracker(timeval tv)
    {
        tr_init_tv = tv;
        tr_base_tv = {0,0};
        tr_print_tv = {0,0};
        tr_flowtable = {};
        tr_initiated = {};
        tr_smap = {};
        tr_pkt_cnt = 0;
        tr_flow_cnt = 0;
        tr_totalbytes = 0;

        // Set handler for Ctrl+C key
        registerEvent();
    }

    Tracker::~Tracker() 
	{
        tr_flowtable.clear();
        tr_initiated.clear();
        tr_smap.clear();
	}

    void Tracker::registerEvent()
    {
        tr_stop = false;
        pump::EventHandler::getInstance().onInterrupted(onInterrupted, &tr_stop);
    }

    int Tracker::addNewStream(pump::Packet* packet)
    {
        Flow client, server;

        client.ip = packet->getLayer<IPv4Layer>()->getHeader()->ip_src;
        server.ip = packet->getLayer<IPv4Layer>()->getHeader()->ip_dst;

        if(packet->isTypeOf(PROTO_TCP))
        {
            client.port = ntohs(packet->getLayer<pump::TcpLayer>()->getHeader()->sport);
            server.port = ntohs(packet->getLayer<pump::TcpLayer>()->getHeader()->dport);
        }
        else
        {
            client.port = ntohs(packet->getLayer<pump::UdpLayer>()->getHeader()->sport);
            server.port = ntohs(packet->getLayer<pump::UdpLayer>()->getHeader()->dport);
        }

        // allocate a structure to hold bidirectional information of the new TCP stream 
        tr_smap[tr_flow_cnt] = {.proto = 0,
                                .init_rtt = {0, 0},
                                .last_syn = {0, 0},
                                .client = client,
                                .server = server};

        return tr_flow_cnt++;
    }

    int Tracker::getStreamNumber(pump::Packet* packet)
    {
        uint32_t hash = hashStream(packet);

        bool isSyn = isTcpSyn(packet);

        // We haven't seen a packet with this converstation yet, so create one
        if (tr_flowtable.find(hash) == tr_flowtable.end())
        {
            // We do not care about truncated flow
            // TCP conversation must begin with 3-way TCP handshaking 
            if(!isSyn && packet->isTypeOf(PROTO_TCP)) return -1;

            // Add it to the list of conversations
            tr_flowtable[hash] = addNewStream(packet);
            tr_initiated[hash] = true;
        }
        // Look up the conversation
        else
        {
            // If we encounter an SYN packet with a hash value already stored in the flow table,
            // this indicate a new session, so the flow table assigns a new stream
            // index to such conversation unless the we had seen SYN as last packet,
            // which is an indication of SYN retransmission
            if (isSyn && tr_initiated[hash] == false)
            {
                tr_flowtable[hash] = addNewStream(packet);
            }

            tr_initiated[hash] = isSyn;
        }
        return tr_flowtable[hash];
    }

    void Tracker::parsePacket(pump::Packet* packet, CaptureConfig* config)
    {
        timeval curr_tv;
        gettimeofday(&curr_tv, NULL);

        uint32_t pk_len = packet->getDataLen();
        int64_t delta_time = time_diff(&curr_tv, &tr_init_tv);

        timeval ref_tv = packet->getTimeStamp();

        if (tr_pkt_cnt == 0) time_update(&tr_base_tv, &ref_tv);

        // Stop reading if we have the maximum number of packets
        // or the capture timer is out
        if (tr_pkt_cnt >= config->maxPacket 
        || time_diff(&ref_tv, &tr_init_tv)/1000000 >= (int64_t)config->maxTime)
        {
            raise(SIGINT);
            return;
        }

        tr_totalbytes += pk_len;
        tr_pkt_cnt++;

        // Show the capturing progress 
        if (delta_time == 0 || time_diff(&ref_tv, &tr_print_tv) >= 31250)
        {
            rusage r_usage;
            getrusage(RUSAGE_SELF, &r_usage);

            // Report an out-of-memory condition and abort
            if(r_usage.ru_maxrss > MEMORY_LIMIT)
                EXIT_WITH_RUNERROR("###ERROR : The process consume too much memory");

            if(config->quitemode) print_progressM(tr_pkt_cnt);
            time_update(&tr_print_tv, &ref_tv);
        }

        if(!packet->isTypeOf(PROTO_TCP) 
        && !packet->isTypeOf(PROTO_UDP))
            return;

        int ss_idx = getStreamNumber(packet);

        // A packet in a truncated flow
        if (ss_idx == -1) return;

        Stream* ss = &(tr_smap[ss_idx]);

        bool peer = isClient(packet, ss);

        // Get the data structures containing flow-level information in
        // the same/reverse direction as the current packet
        Flow* fwd = &(peer ? ss->client : ss->server);
        Flow* rev = &(peer ? ss->server : ss->client);

        parseCommon(packet, fwd, rev);

        if (packet->isTypeOf(PROTO_ETHERNET))
        {
            parseEth(packet, fwd, rev);
            ss->proto |= PROTO_ETHERNET;
        }

        if (packet->isTypeOf(PROTO_IPv4))
        {
            parseIPv4(packet, fwd, rev);
            ss->proto |= PROTO_IPv4;
        }

        if (packet->isTypeOf(PROTO_ICMP))
        {
            parseIcmp(packet, fwd, rev);
            ss->proto |= PROTO_ICMP;
        }

        if (packet->isTypeOf(PROTO_TCP))
        {
            parseTcp(packet, ss, fwd, rev);
            ss->proto |= PROTO_TCP;
        }

        if (packet->isTypeOf(PROTO_UDP))
        {
            // TODO : parseUdp(packet, ss, fwd, rev);
            ss->proto |= PROTO_UDP;
        }

        if(!config->quitemode
        && fwd->st_common.pkt_cnt + rev->st_common.pkt_cnt == 1)
        {
            print_progressN(ss);
        }
    }   

    void Tracker::saveStats(CaptureConfig* config)
    {
        std::map<uint32_t, Stream>::iterator it;

        FILE* f = fopen(config->outputFileTo.c_str(), "w");
        if (f == NULL)
            EXIT_WITH_RUNERROR("ERROR : Could not open ouput csv file");

        // Header of the output Csv file
        fprintf(f,  "src, dst, stream_no., proto, #pkt, dur,"
                    "#pkt_fwd, pkt_fwd/sec, bytes_fwd/sec, dur_fwd,"
                    "pkt_len_fwd_max, pkt_len_fwd_min, pkt_len_fwd_avg, iat_fwd_max, iat_fwd_min, iat_fwd_avg,"
                    "#pkt_rev, pkt_rev/sec, bytes_rev/sec, dur_rev,"
                    "pkt_len_rev_max, pkt_len_rev_min, pkt_len_rev_avg, iat_rev_max, iat_rev_min, iat_rev_avg,"
                    "%%eth_padd_fwd, eth_padd_len_fwd_max, eth_padd_len_fwd_min, eth_padd_len_fwd_avg,"
                    "%%eth_padd_rev, eth_padd_len_rev_max, eth_padd_len_rev_min, eth_padd_len_rev_avg,"
                    "ip_dscp_fwd, %%ip_df_fwd, %%ip_mf_fwd, ip_ttl_fwd_max, ip_ttl_fwd_min, ip_ttl_fwd_avg,"
                    "%%ip_not-ect_fwd, %%ip_ect0_fwd, %%ip_ect1_fwd, %%ip_ce_fwd,"
                    "ip_fragoff_fwd_max, ip_fragoff_fwd_min, ip_fragoff_fwd_avg,"
                    "ip_dscp_rev, %%ip_df_rev, %%ip_mf_rev, ip_ttl_rev_max, ip_ttl_rev_min, ip_ttl_rev_avg,"
                    "%%ip_not-ect_rev, %%ip_ect0_rev, %%ip_ect1_rev, %%ip_ce_rev,"
                    "ip_fragoff_rev_max, ip_fragoff_rev_min, ip_fragoff_rev_avg,"
                    "%%icmp_pkt_cnt_fwd, %%icmp_echo_rep_fwd, %%icmp_echo_req_fwd, %%icmp_net_unr_fwd, %%icmp_host_unr_fwd,"
                    "%%icmp_proto_unr_fwd, %%icmp_port_unr_fwd, %%icmp_host_prhb_fwd, %%icmp_comm_prhb_fwd, %%icmp_time_exceed_fwd,"
                    "%%icmp_pkt_cnt_rev, %%icmp_echo_rep_rev, %%icmp_echo_req_rev, %%icmp_net_unr_rev, %%icmp_host_unr_rev,"
                    "%%icmp_proto_unr_rev, %%icmp_port_unr_rev, %%icmp_host_prhb_rev, %%icmp_comm_prhb_rev, %%icmp_time_exceed_rev,"
                    "%%pkt_with_pay_fwd, pay_len_fwd_max, pay_len_fwd_min, pay_len_fwd_avg,"
                    "%%pkt_with_pay_rev, pay_len_rev_max, pay_len_rev_min, pay_len_rev_avg,"
                    "%%tcp_ack_frame_fwd, tcp_acked_frame_max_fwd, tcp_acked_frame_min_fwd, tcp_acked_frame_avg_fwd,"
                    "tcp_seg_splits_fwd_max, tcp_seg_splits_fwd_min, tcp_seg_splits_fwd_avg,"
                    "tcp_ack_rtt_fwd_max, tcp_ack_rtt_fwd_min, tcp_ack_rtt_fwd_avg, %%tcp_nonzero_ack_fwd, %%tcp_acked_unseen_fwd,"
                    "%%tcp_pkt_with_bif_fwd, tcp_bif_fwd_max, tcp_bif_fwd_min, tcp_bif_fwd_avg,"
                    "%%tcp_dup_ack_fwd, %%tcp_fast_retran_fwd, %%tcp_keep_alive_fwd,"
                    "%%tcp_keep_alive_ack_fwd, %%tcp_lost_seg_fwd, %%tcp_out_of_order_fwd,"
                    "%%tcp_pkt_with_pb_fwd, tcp_pb_fwd_max, tcp_pb_fwd_min, tcp_pb_fwd_avg,"
                    "%%tcp_retran_fwd, tcp_rto_fwd_max, tcp_rto_fwd_min, tcp_rto_fwd_avg,"
                    "%%tcp_spur_retran_fwd, %%tcp_win_full_fwd, %%tcp_win_update_fwd,"
                    "%%tcp_zwin_fwd, %%tcp_zwin_probe_fwd, %%tcp_zwin_probe_ack_fwd,"
                    "%%tcp_FIN_fwd, %%tcp_SYN_fwd, %%tcp_RST_fwd, %%tcp_PSH_fwd,"
                    "%%tcp_ACK_fwd, %%tcp_URG_fwd, %%tcp_ECE_fwd, %%tcp_CWR_fwd,"
                    "%%tcp_has_opt_fwd, tcp_opt_len_fwd_max, tcp_opt_len_fwd_min, tcp_opt_len_fwd_avg,"
                    "tcp_opt_cnt_fwd_max, tcp_opt_cnt_fwd_min, tcp_opt_cnt_fwd_avg,"
                    "%%tcp_opt_sack_fwd, %%tcp_opt_ts_fwd, %%tcp_opt_tfo_fwd, %%tcp_opt_mptcp_fwd,"
                    "tcp_opt_win_scale_fwd, tcp_opt_mss_fwd, tcp_opt_sack_perm_fwd,"
                    "tcp_win_fwd_max, tcp_win_fwd_min, tcp_win_fwd_avg,"
                    "%%tcp_ack_frame_rev, tcp_acked_frame_max_rev, tcp_acked_frame_min_rev, tcp_acked_frame_avg_rev,"
                    "tcp_seg_splits_rev_max, tcp_seg_splits_rev_min, tcp_seg_splits_rev_avg,"
                    "tcp_ack_rtt_rev_max, tcp_ack_rtt_rev_min, tcp_ack_rtt_rev_avg, %%tcp_nonzero_ack_rev, %%tcp_acked_unseen_rev,"
                    "%%tcp_pkt_with_bif_rev, tcp_bif_rev_max, tcp_bif_rev_min, tcp_bif_rev_avg,"
                    "%%tcp_dup_ack_rev, %%tcp_fast_retran_rev, %%tcp_keep_alive_rev,"
                    "%%tcp_keep_alive_ack_rev, %%tcp_lost_seg_rev, %%tcp_out_of_order_rev,"
                    "%%tcp_pkt_with_pb_rev, tcp_pb_rev_max, tcp_pb_rev_min, tcp_pb_rev_avg,"
                    "%%tcp_retran_rev, tcp_rto_rev_max, tcp_rto_rev_min, tcp_rto_rev_avg,"
                    "%%tcp_spur_retran_rev, %%tcp_win_full_rev, %%tcp_win_update_rev,"
                    "%%tcp_zwin_rev, %%tcp_zwin_probe_rev, %%tcp_zwin_probe_ack_rev,"
                    "%%tcp_FIN_rev, %%tcp_SYN_rev, %%tcp_RST_rev, %%tcp_PSH_rev,"
                    "%%tcp_ACK_rev, %%tcp_URG_rev, %%tcp_ECE_rev, %%tcp_CWR_rev,"
                    "%%tcp_has_opt_rev, tcp_opt_len_rev_max, tcp_opt_len_rev_min, tcp_opt_len_rev_avg,"
                    "tcp_opt_cnt_rev_max, tcp_opt_cnt_rev_min, tcp_opt_cnt_rev_avg,"
                    "%%tcp_opt_sack_rev, %%tcp_opt_ts_rev, %%tcp_opt_tfo_rev, %%tcp_opt_mptcp_rev,"
                    "tcp_opt_win_scale_rev, tcp_opt_mss_rev, tcp_opt_sack_perm_rev,"
                    "tcp_win_rev_max, tcp_win_rev_min, tcp_win_rev_avg,"
                    "tcp_init_rtt\n");

        for(it = tr_smap.begin(); it != tr_smap.end(); it++)
        {
            // User wants to stop the processing, close the merge Mod
            if(tr_stop) stop_signal_callback_handler(SIGINT);

            char cIP[16], sIP[16];

            uint32_t ss_idx = it->first;
            Stream* ss = &(it->second);

            timeval ref_tv;
            gettimeofday(&ref_tv, NULL);

            // Show the merging progress
            if (ss_idx == 0 || ss_idx + 1 == tr_flow_cnt || time_diff(&ref_tv, &tr_print_tv) >= 31250)
            {
                print_progressA(ss_idx + 1, tr_flow_cnt);
                time_update(&tr_print_tv, &ref_tv);
            }

            Flow* fwd = &ss->client;
            Flow* rev = &ss->server;

            parseIPV4(cIP, fwd->ip);
            parseIPV4(sIP, rev->ip);

            fprintf(f, "%s:%d,%s:%d,%.8d,", cIP, fwd->port, sIP, rev->port, ss_idx);

            if(ss->proto & PROTO_UDP) fprintf(f, "UDP");
            else if(ss->proto & PROTO_TCP) fprintf(f, "TCP");
            else if(ss->proto & PROTO_IPv4) fprintf(f, "IP");
            else if(ss->proto & PROTO_ICMP) fprintf(f, "ICMP");
            else if(ss->proto & PROTO_ETHERNET) fprintf(f, "Ethernet");
            else fprintf(f, "Unknown");

            uint32_t c_pkt = fwd->st_common.pkt_cnt;
            uint32_t s_pkt = rev->st_common.pkt_cnt;
            uint32_t t_pkt = c_pkt + s_pkt;

            double t_dur;
            
            if (c_pkt == 0)
            {
                t_dur = time_diff(&rev->st_common.last_tv, &rev->st_common.base_tv);
            }
            else if (s_pkt == 0)
            {
                t_dur = time_diff(&fwd->st_common.last_tv, &fwd->st_common.base_tv);
            }
            else
            {
                t_dur = time_tot(&fwd->st_common.base_tv, &rev->st_common.base_tv,
                                 &fwd->st_common.last_tv, &rev->st_common.last_tv);
            }

            fprintf(f, ",%d,%.6f", t_pkt, t_dur/1000000);

            calCommon(config, f, fwd, c_pkt);
            calCommon(config, f, rev, s_pkt);
            
            calEth(config, f, fwd, ss->proto & PROTO_ETHERNET ? c_pkt : 0);
            calEth(config, f, rev, ss->proto & PROTO_ETHERNET ? s_pkt : 0);

            calIPv4(config, f, fwd, ss->proto & PROTO_IPv4 ? c_pkt : 0);
            calIPv4(config, f, rev, ss->proto & PROTO_IPv4 ? s_pkt : 0);

            calIcmp(config, f, fwd, ss->proto & PROTO_ICMP ? c_pkt : 0);
            calIcmp(config, f, rev, ss->proto & PROTO_ICMP ? s_pkt : 0);

            calTransport(config, f, fwd, ss->proto & (PROTO_TCP | PROTO_UDP) ? c_pkt : 0);
            calTransport(config, f, rev, ss->proto & (PROTO_TCP | PROTO_UDP) ? s_pkt : 0);

            calTcp(config, f, fwd, ss->proto & PROTO_TCP ? c_pkt : 0);
            calTcp(config, f, rev, ss->proto & PROTO_TCP ? s_pkt : 0);

            if((ss->proto & PROTO_TCP) && 
            !time_isZero(&ss->init_rtt))
            {
                fprintf(f, ",%.6f", time_raws(&ss->init_rtt));
            }
            else
            {
                fprintf(f, ",%c", config->mark_null ? '-' : '0');
            }
    
            fprintf(f, "\n");
                
        }
        fclose(f);             
        printf("\n**Total Stream#**=========================================== (%u)", tr_flow_cnt);
    }

    void Tracker::close()
    {
        tr_flowtable.clear();
        tr_initiated.clear();
        tr_smap.clear(); 
    }

}