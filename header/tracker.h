/* tracker.h
 * 
 * routines to calculate stats of each IP flow
 *  
 * NetFI - a fast and simple tool to analyze the network flow (Internet Protocol family) 
 */

#ifndef PUMP_TRACKER
#define PUMP_TRACKER

#include <stdint.h>

#include <map>
#include <string>
#include <utility>

#include "packet.h"
#include "layer-ip.h"
#include "layer-tcp.h"
#include "layer-udp.h"

#define F_SAW_SYN             0x1
#define F_SAW_SYNACK          0x2
#define F_END_SYN_HS          0x4
#define F_END_FIN_HS          0x8
#define F_BASE_SEQ_SET       0x10

#define TCP_A_ACK_LOST_PACKET                0x1
#define TCP_A_DUPLICATE_ACK                  0x2
#define TCP_A_KEEP_ALIVE                     0x4
#define TCP_A_KEEP_ALIVE_ACK                 0x8
#define TCP_A_LOST_PACKET                   0x10
#define TCP_A_FAST_RETRANSMISSION           0x20
#define TCP_A_OUT_OF_ORDER                  0x40
#define TCP_A_SPURIOUS_RETRANSMISSION       0x80
#define TCP_A_RETRANSMISSION               0x100
#define TCP_A_WINDOW_FULL                  0x200
#define TCP_A_WINDOW_UPDATE                0x400
#define TCP_A_ZERO_WINDOW                  0x800
#define TCP_A_ZERO_WINDOW_PROBE           0x1000
#define TCP_A_ZERO_WINDOW_PROBE_ACK       0x2000

namespace pump
{

    struct CaptureConfig
    {
        uint32_t maxPacket;
        uint32_t maxTime;
        bool quitemode;
        bool mark_null;
        std::string outputFileTo;
    };

    struct CommonStat
    {
        uint32_t pkt_cnt = 0;
        timeval base_tv;
        timeval last_tv;
        numeric_stat<uint16_t> pktlen;
        time_stat intarr_time;
    };

    struct EthStat
    {
        uint32_t pad_cnt = 0;
        numeric_stat<uint16_t> padlen;
    };

    struct IPv4Stat
    {
        uint32_t df_cnt = 0;
        uint32_t mf_cnt = 0;
        uint32_t fragoff_cnt = 0;
        uint32_t ecn_none_cnt = 0;
        uint32_t ecn_ect0_cnt = 0;
        uint32_t ecn_ect1_cnt = 0;
        uint32_t ecn_ce_cnt = 0;
        uint8_t dscp = 0;
        numeric_stat<uint8_t> ttl;
        numeric_stat<uint16_t> fragoff;
    };

    struct IcmpStat
    {
        uint32_t icmp_cnt = 0;
        uint32_t echo_reply = 0;
        uint32_t echo_request = 0;
        uint32_t net_unreachable = 0;
        uint32_t host_unreachable = 0;
        uint32_t proto_unreachable = 0;
        uint32_t port_unreachable = 0;
        uint32_t host_prohibited = 0;
        uint32_t comm_prohibited = 0;
        uint32_t time_exceeded = 0;
    };

    struct TransportStat
    {   
        uint32_t has_pay = 0;
        numeric_stat<uint16_t> paylen;
    };

    struct TcpStat
    {
        uint32_t a_ack_none = 0;
        uint32_t a_acked_unseen = 0;
        uint32_t a_ack_frame_cnt = 0;
        uint32_t a_bif_cnt = 0;
        uint32_t a_dup_ack = 0;
        uint32_t a_fast_retrans = 0;
        uint32_t a_keep_alive = 0;
        uint32_t a_keep_alive_ack = 0;
        uint32_t a_lost_segment = 0;
        uint32_t a_out_of_order = 0;
        uint32_t a_push_cnt = 0;
        uint32_t a_retrans = 0;
        uint32_t a_spur_retrans = 0;
        uint32_t a_window_full = 0;
        uint32_t a_window_update = 0;
        uint32_t a_zero_window = 0;
        uint32_t a_zero_window_probe = 0;
        uint32_t a_zero_window_probe_ack = 0;
        uint32_t f_ack = 0;
        uint32_t f_cwr = 0;
        uint32_t f_ece = 0;
        uint32_t f_fin = 0;
        uint32_t f_psh = 0;
        uint32_t f_rst = 0;
        uint32_t f_syn = 0;
        uint32_t f_urg = 0;
        uint32_t has_opt = 0;
        int8_t opt_win_scale = -1;
        int8_t opt_sack_perm = -1;
        int16_t opt_mss = -1;
        uint32_t opt_sack_cnt = 0;
        uint32_t opt_timestamp_cnt = 0;
        uint32_t opt_tfo_cnt = 0;
        uint32_t opt_mptcp_cnt = 0;
        numeric_stat<uint8_t> optcnt;
        numeric_stat<uint8_t> optlen;
        numeric_stat<uint32_t> win;
        numeric_stat<uint32_t> bif;
        numeric_stat<uint32_t> push_bytes;
        numeric_stat<uint32_t> acked_frame_cnt;
        numeric_stat<uint32_t> seg_frame_cnt;
        time_stat ack_rtt;
        time_stat rto;
    };   

    struct Flow 
    {
        CommonStat st_common;
        EthStat st_eth;
        IPv4Stat st_ip;
        IcmpStat st_icmp;
        TransportStat st_trans;
        TcpStat st_tcp;
        uint16_t last_fragoff = 0;
        uint16_t flags = 0;
        uint16_t a_flags = 0;
        uint32_t baseseq = 0;
        uint32_t ip = 0;
        uint16_t port = 0;
        int16_t win_scale = -1;
        uint32_t win = 0xFFFFFFF;
        uint32_t nextseq = 0;
        uint32_t lastack = 0;
        uint32_t max_seq_acked = 0;
        uint32_t dup_ack_cnt = 0;
        uint32_t seg_idx = 0;
        uint32_t push_bytes = 0;
        timeval lastack_time = {};
        timeval nextseq_time = {};
        timeval rto_tv = {};
        bool valid_bif = true;
        bool push_set_last = false;
        tcp_unacked *lastseg = NULL;
    };

    struct Stream 
    {
        uint8_t proto;
        timeval init_rtt;
        timeval last_syn;
        Flow client;
        Flow server;
    };

    uint32_t hashStream(pump::Packet* packet);

    bool isTcpSyn(pump::Packet* packet);

    bool isClient(pump::Packet* packet, Stream* ss);

    void calCommon(CaptureConfig* config, FILE* f, Flow* flow, uint32_t pkt_cnt);

    void calEth(CaptureConfig* config, FILE* f, Flow* flow, uint32_t pkt_cnt);

    void calIPv4(CaptureConfig* config, FILE* f, Flow* flow, uint32_t pkt_cnt);

    void calIcmp(CaptureConfig* config, FILE* f, Flow* flow, uint32_t pkt_cnt);

    void calTransport(CaptureConfig* config, FILE* f, Flow* flow, uint32_t pkt_cnt);

    void calTcp(CaptureConfig* config, FILE* f, Flow* flow, uint32_t pkt_cnt);

    void parseCommon(pump::Packet* packet, Flow* fwd, Flow* rev);

    void parseEth(pump::Packet* packet, Flow* fwd, Flow* rev);

    void parseIPv4(pump::Packet* packet, Flow* fwd, Flow* rev);

    void parseIcmp(pump::Packet* packet, Flow* fwd, Flow* rev);

    void parseTcp(pump::Packet* packet, Stream* ss, Flow* fwd, Flow* rev);

    void parseUdp(pump::Packet* packet, Flow* fwd, Flow* rev);

    class Tracker
    {

        private:

            uint32_t tr_pkt_cnt;
            uint32_t tr_flow_cnt;
            uint64_t tr_totalbytes;

            bool tr_stop;

            timeval tr_init_tv, tr_base_tv, tr_print_tv;

            std::map<uint32_t, int> tr_flowtable;

            std::map<uint32_t, bool> tr_initiated;

            std::map<uint32_t, Stream> tr_smap;

            int addNewStream(pump::Packet* packet);

            int getStreamNumber(pump::Packet* packet, CaptureConfig* config);

        public:

            Tracker(timeval tv);

            ~Tracker();

            void registerEvent();

            uint32_t getTotalPacket() { return tr_pkt_cnt; };

            uint32_t getTotalStream() { return tr_flow_cnt; }

            uint64_t getTotalByteLen() { return tr_totalbytes; }

            timeval* getStartTime() { return &tr_init_tv; } 

            bool isTerminated() {return tr_stop; }

            void parsePacket(pump::Packet* packet, CaptureConfig* config);

            void saveStats(CaptureConfig* config);

    };

}

#endif