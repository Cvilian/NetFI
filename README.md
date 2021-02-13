NefFI
==========
`NetFI` is a fast and simple tool to analyze the network flow (internet protocol family). It is a libpcap-based application to parse a network data stream and extract more than 200 kinds of flow-statistical information. 


## Table Of Contents

- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)
- [Appendix](#appendix)

## Description
For anyone who aims to manage and monitor the networked system, it would be a good choice. `NetFI` helps you gain wide visibility in TCP/UDP channels.  Our application is quick enough to handle more than 100,000 packets within a second and so intuitive that the user probably makes familiar use of it easily. `NetFI` captures bidirectional network flows through a given pcap file or even a live network interface, resulting in detailed and diverse statistics about Ethernet, IP, ICMP, TCP, and UDP layers. The output stats will be written in a csv file format with columns labeled for each flow, namely source/destination IP:port, flow number, protocol, and hundreds of statistical features (See appendix for all available information). Hopefully, it could be helpful to the expert in various network research fields.


## Installation

#### Build on Linux:

```shell
$ sudo apt-get install libpcap-dev
$ sudo apt-get update
$ sudo apt-get upgrade

$ git clone https://github.com/cvlian/NetFI
$ cd NetFI
$ sudo make all
```

## Usage
    
    Usage: NetFI [options] ...
    
    Capture packets:
        -i <interface>   : Name of the network interface
        -r <input-file>  : Read packet data from <input-file>
    Capture stop conditions:
        -c <count>       : Set the maximum number of packets to read
        -d <duration>    : Stop after <duration> seconds
    Processing:
        -q               : Print less-verbose flow information
        -s               : Mark a N/A value as '-', instead of a zero value
    Output:
        -w <output-file> : Write all flow-statistical info to <output-file>
                           (or write its results to stdout)
    Others:
        -h               : Displays this help message and exits


#### Network inspection with Pcap File:
    $ sudo netfi -r example.pcap

It will print the session information of corresponding communicating peers. 


![ex_screenshot](./img/test.png)


#### Network inspection on Live Network Interface (and save statistics in example.csv):
    $ sudo netfi -i eth0 -w example.csv


## License
NetFI is provided under a BSD 3-Clause License.


## Appendix
Our tool can offer total 211 flow features listed in the table below:

    +------+--------------------------+-----------------------------------------------------------------------------------+---------+
    | No.  | Notation                 | Description                                                                       | Type    |
    +======+==========================+===================================================================================+=========+
    | 1.   | src                      | Source host                                                                       | IP:port |
    | 2.   | dst                      | Destination host                                                                  | IP:port |
    | 3.   | stream_no.               | Flow Index                                                                        | -       |
    | 4.   | proto                    | Protocol                                                                          | -       |
    | 5.   | #pkt                     | Total packets                                                                     | #       |
    | 6.   | duration                 | Flow duration                                                                     | sec     |
    | 7.   | #pkt_fwd                 | Total packets in forward direction                                                | #       |
    | 8.   | pkt_fwd/sec              | Number of packets per second in forward direction                                 | #/sec   |
    | 9.   | bytes_fwd/sec            | Number of bytes per second in forward direction                                   | #/sec   |
    | 10.  | duration_fwd             | Total duration in forward direction                                               | sec     |
    | 11.  | pkt_len_fwd_max          | Maximum packet length in forward direction                                        | number  |
    | 12.  | pkt_len_fwd_min          | Minimum packet length in forward direction                                        | number  |
    | 13.  | pkt_len_fwd_avg          | Average packet length in forward direction                                        | number  |
    | 14.  | iat_fwd_max              | Maximum inter-arrival time in forward direction                                   | sec     |
    | 15.  | iat_fwd_min              | Minimum inter-arrival time in forward direction                                   | sec     |
    | 16.  | iat_fwd_avg              | Average inter-arrival time in forward direction                                   | sec     |
    | 17.  | #pkt_rev                 | Total packets in reverse direction                                                | #       |
    | 18.  | pkt_rev/sec              | Number of packets per second in reverse direction                                 | #/sec   |
    | 19.  | bytes_rev/sec            | Number of bytes per second in reverse direction                                   | #/sec   |
    | 20.  | duration_rev             | Total duration in reverse direction                                               | sec     |
    | 21.  | pkt_len_rev_max          | Maximum packet length in reverse direction                                        | number  |
    | 22.  | pkt_len_rev_min          | Minimum packet length in reverse direction                                        | number  |
    | 23.  | pkt_len_rev_avg          | Average packet length in reverse direction                                        | number  |
    | 24.  | iat_rev_max              | Maximum inter-arrival time in reverse direction                                   | sec     |
    | 25.  | iat_rev_min              | Minimum inter-arrival time in reverse direction                                   | sec     |
    | 26.  | iat_rev_avg              | Average inter-arrival time in reverse direction                                   | sec     |
    | 27.  | %eth_padd_fwd            | Ratio of packets with ethernet padding in forward direction                       | %       |
    | 28.  | eth_padd_len_fwd_max     | Maximum ethernet padding size in forward direction                                | number  |
    | 29.  | eth_padd_len_fwd_min     | Minimum ethernet padding size in forward direction                                | number  |
    | 30.  | eth_padd_len_fwd_avg     | Average ethernet padding size in forward direction                                | number  |
    | 31.  | %eth_padd_rev            | Ratio of packets with ethernet padding in reverse direction                       | %       |
    | 32.  | eth_padd_len_rev_max     | Maximum ethernet padding size in reverse direction                                | number  |
    | 33.  | eth_padd_len_rev_min     | Minimum ethernet padding size in reverse direction                                | number  |
    | 34.  | eth_padd_len_rev_avg     | Average ethernet padding size in reverse direction                                | number  |
    | 35.  | ip_dscp_fwd              | Differentiated Service Codepoint in forward direction                             | -       |
    | 36.  | %ip_df_fwd               | Ratio of packets with DF (Don't Fragement) bit in forward direction               | %       |
    | 37.  | %ip_mf_fwd               | Ratio of packets with MF (More Fragement) bit in forward direction                | %       |
    | 38.  | ip_ttl_fwd_max           | Maximum Time to Live (TTL) in forward direction                                   | number  |
    | 39.  | ip_ttl_fwd_min           | Minimum Time to Live (TTL) in forward direction                                   | number  |
    | 40.  | ip_ttl_fwd_avg           | Average Time to Live (TTL) in forward direction                                   | number  |
    | 41.  | %ip_not-ect_fwd          | Ratio of packets without supporting ECN in forward direction                      | %       |
    | 42.  | %ip_ect0_fwd             | Ratio of packets with supporting ECT0 in forward direction                        | %       |
    | 43.  | %ip_ect1_fwd             | Ratio of packets with supporting ECT1 in forward direction                        | %       |
    | 44.  | %ip_ce_fwd               | Ratio of packets with supporting CE in forward direction                          | %       |
    | 45.  | ip_fragoff_fwd_max       | Maximum Fragment offset without MF bit in forward direction                       | number  |
    | 46.  | ip_fragoff_fwd_min       | Minimum Fragment offset without MF bit in forward direction                       | number  |
    | 47.  | ip_fragoff_fwd_avg       | Average Fragment offset without MF bit in forward direction                       | number  |
    | 48.  | ip_dscp_rev              | Differentiated Service Codepoint in reverse direction                             | -       |
    | 49.  | %ip_df_rev               | Ratio of packets with DF (Don't Fragement) bit in reverse direction               | %       |
    | 50.  | %ip_mf_rev               | Ratio of packets with MF (More Fragement) bit in reverse direction                | %       |
    | 51.  | ip_ttl_rev_max           | Maximum Time to Live (TTL) in reverse direction                                   | number  |
    | 52.  | ip_ttl_rev_min           | Minimum Time to Live (TTL) in reverse direction                                   | number  |
    | 53.  | ip_ttl_rev_avg           | Average Time to Live (TTL) in reverse direction                                   | number  |
    | 54.  | %ip_not-ect_rev          | Ratio of packets without supporting ECN in reverse direction                      | %       |
    | 55.  | %ip_ect0_rev             | Ratio of packets with supporting ECT0 in reverse direction                        | %       |
    | 56.  | %ip_ect1_rev             | Ratio of packets with supporting ECT1 in reverse direction                        | %       |
    | 57.  | %ip_ce_rev               | Ratio of packets with supporting CE in reverse direction                          | %       |
    | 58.  | ip_fragoff_rev_max       | Maximum Fragment offset without MF bit in reverse direction                       | number  |
    | 59.  | ip_fragoff_rev_min       | Minimum Fragment offset without MF bit in reverse direction                       | number  |
    | 60.  | ip_fragoff_rev_avg       | Average Fragment offset without MF bit in reverse direction                       | number  |
    | 61.  | %icmp_pkt_cnt_fwd        | Ratio of packets with ICMP frame in forward direction                             | %       |
    | 62.  | %icmp_echo_rep_fwd       | Ratio of packets with 'Echo Reply' message in forward direction                   | %       |
    | 63.  | %icmp_echo_req_fwd       | Ratio of packets with 'Echo Request' message in forward direction                 | %       |
    | 64.  | %icmp_net_unr_fwd        | Ratio of packets with 'Network Unreachable' message in forward direction          | %       |
    | 65.  | %icmp_host_unr_fwd       | Ratio of packets with 'Host Unreachable' message in forward direction             | %       |
    | 66.  | %icmp_proto_unr_fwd      | Ratio of packets with 'Protocol Unreachable' message in forward direction         | %       |
    | 67.  | %icmp_port_unr_fwd       | Ratio of packets with 'Port Unreachable' message in forward direction             | %       |
    | 68.  | %icmp_host_prhb_fwd      | Ratio of packets with 'Destination Host Prohibited' message in forward direction  | %       |
    | 69.  | %icmp_comm_prhb_fwd      | Ratio of packets with 'Communication Prohibited' message in forward direction     | %       |
    | 70.  | %icmp_time_exceed_fwd    | Ratio of packets with 'Time exceeded' message in forward direction                | %       |
    | 71.  | %icmp_pkt_cnt_rev        | Ratio of packets with ICMP frame in reverse direction                             | %       |
    | 72.  | %icmp_echo_rep_rev       | Ratio of packets with 'Echo Reply' message in reverse direction                   | %       |
    | 73.  | %icmp_echo_req_rev       | Ratio of packets with 'Echo Request' message in reverse direction                 | %       |
    | 74.  | %icmp_net_unr_rev        | Ratio of packets with 'Network Unreachable' message in reverse direction          | %       |
    | 75.  | %icmp_host_unr_rev       | Ratio of packets with 'Host Unreachable' message in reverse direction             | %       |
    | 76.  | %icmp_proto_unr_rev      | Ratio of packets with 'Protocol Unreachable' message in reverse direction         | %       |
    | 77.  | %icmp_port_unr_rev       | Ratio of packets with 'Port Unreachable' message in reverse direction             | %       |
    | 78.  | %icmp_host_prhb_rev      | Ratio of packets with 'Destination Host Prohibited' message in reverse direction  | %       |
    | 79.  | %icmp_comm_prhb_rev      | Ratio of packets with 'Communication Prohibited' message in reverse direction     | %       |
    | 80.  | %icmp_time_exceed_rev    | Ratio of packets with 'Time exceeded' message in reverse direction                | %       |
    | 81.  | %pkt_with_pay_fwd        | Ratio of packets with TCP/UDP payload in forward direction                        | %       |
    | 82.  | pay_len_fwd_max          | Maximum TCP/UDP payload length in forward direction                               | number  |
    | 83.  | pay_len_fwd_min          | Minimum TCP/UDP payload length in forward direction                               | number  |
    | 84.  | pay_len_fwd_avg          | Average TCP/UDP payload length in forward direction                               | number  |
    | 85.  | %pkt_with_pay_rev        | Ratio of packets with TCP/UDP payload in reverse direction                        | %       |
    | 86.  | pay_len_rev_max          | Maximum TCP/UDP payload length in reverse direction                               | number  |
    | 87.  | pay_len_rev_min          | Minimum TCP/UDP payload length in reverse direction                               | number  |
    | 88.  | pay_len_rev_avg          | Average TCP/UDP payload length in reverse direction                               | number  |
    | 89.  | %tcp_ack_frame_fwd       | Ratio of packets with ACK to a previous segment in forward direction              | %       |
    | 90.  | tcp_acked_frame_max_fwd  | Maximum number of frame acked at once in forward direction                        | #       |
    | 91.  | tcp_acked_frame_min_fwd  | Minimum number of frame acked at once in forward direction                        | #       |
    | 92.  | tcp_acked_frame_avg_fwd  | Average number of frame acked at once in forward direction                        | #       |
    | 93.  | tcp_seg_splits_fwd_max   | Maximum number of segment splits in forward direction                             | #       |
    | 94.  | tcp_seg_splits_fwd_min   | Minimum number of segment splits in forward direction                             | #       |
    | 95.  | tcp_seg_splits_fwd_avg   | Average number of segment splits in forward direction                             | #       |
    | 96.  | tcp_ack_rtt_fwd_max      | Maximum Round Trip TIme (RTT) to ACK in forward direction                         | sec     |
    | 97.  | tcp_ack_rtt_fwd_min      | Minimum Round Trip TIme (RTT) to ACK in forward direction                         | sec     |
    | 98.  | tcp_ack_rtt_fwd_avg      | Average Round Trip TIme (RTT) to ACK in forward direction                         | sec     |
    | 99.  | %tcp_nonzero_ack_fwd     | Ratio of packets with nonzero ack while ACK flag is not set in forward direction  | %       |
    | 100. | %tcp_acked_unseen_fwd    | Ratio of acked lost packets in forward direction                                  | %       |
    | 101. | %tcp_pkt_with_bif_fwd    | Ratio of packets with bytes in flight in forward direction                        | %       |
    | 102. | tcp_bif_fwd_max          | Maximum bytes in flight in forward direction                                      | number  |
    | 103. | tcp_bif_fwd_min          | Minimum bytes in flight in forward direction                                      | number  |
    | 104. | tcp_bif_fwd_avg          | Average bytes in flight in forward direction                                      | number  |
    | 105. | %tcp_dup_ack_fwd         | Ratio of packets with duplicated ack in forward direction                         | %       |
    | 106. | %tcp_fast_retran_fwd     | Ratio of fast-retransmission in forward direction                                 | %       |
    | 107. | %tcp_keep_alive_fwd      | Ratio of keep-alive in forward direction                                          | %       |
    | 108. | %tcp_keep_alive_ack_fwd  | Ratio of keep-alive ACK in forward direction                                      | %       |
    | 109. | %tcp_lost_seg_fwd        | Ratio of packets missed some previous segments in forward direction               | %       |
    | 110. | %tcp_out_of_order_fwd    | Ratio of out-of-order segments in forward direction                               | %       |
    | 111. | %tcp_pkt_with_pb_fwd     | Ratio of packet sent bytes since last PSH flag in forward direction               | %       |
    | 112. | tcp_pb_fwd_max           | Maximum push bytes right before occurence of PSH flag in forward direction        | number  |
    | 113. | tcp_pb_fwd_min           | Minimum push bytes right before occurence of PSH flag in forward direction        | number  |
    | 114. | tcp_pb_fwd_avg           | Average push bytes right before occurence of PSH flag in forward direction        | number  |
    | 115. | %tcp_retran_fwd          | Ratio of retransmission in forward direction                                      | %       |
    | 116. | tcp_rto_fwd_max          | Maximum retransmission time-out in forward direction                              | sec     |
    | 117. | tcp_rto_fwd_min          | Minimum retransmission time-out in forward direction                              | sec     |
    | 118. | tcp_rto_fwd_avg          | Average retransmission time-out in forward direction                              | sec     |
    | 119. | %tcp_spur_retran_fwd     | Ratio of spurious retransmission in forward direction                             | %       |
    | 120. | %tcp_win_full_fwd        | Ratio of packets with full window in forward direction                            | %       |
    | 121. | %tcp_win_update_fwd      | Ratio of packets with TCP window update in forward direction                      | %       |
    | 122. | %tcp_zwin_fwd            | Ratio of packets with zero window in forward direction                            | %       |
    | 123. | %tcp_zwin_probe_fwd      | Ratio of zero-window-probe in forward direction                                   | %       |
    | 124. | %tcp_zwin_probe_ack_fwd  | Ratio of zero-window-probe ACK in forward direction                               | %       |
    | 125. | %tcp_FIN_fwd             | Ratio of FIN flags in forward direction                                           | %       |
    | 126. | %tcp_SYN_fwd             | Ratio of SYN flags in forward direction                                           | %       |
    | 127. | %tcp_RST_fwd             | Ratio of RST flags in forward direction                                           | %       |
    | 128. | %tcp_PSH_fwd             | Ratio of PSH flags in forward direction                                           | %       |
    | 129. | %tcp_ACK_fwd             | Ratio of ACK flags in forward direction                                           | %       |
    | 130. | %tcp_URG_fwd             | Ratio of URG flags in forward direction                                           | %       |
    | 131. | %tcp_ECE_fwd             | Ratio of ECE flags in forward direction                                           | %       |
    | 132. | %tcp_CWR_fwd             | Ratio of CWR flags in forward direction                                           | %       |
    | 133. | %tcp_has_opt_fwd         | Ratio of packets with TCP options in forward direction                            | %       |
    | 134. | tcp_opt_len_fwd_max      | Maximum TCP option length in forward direction                                    | number  |
    | 135. | tcp_opt_len_fwd_min      | Minimum TCP option length in forward direction                                    | number  |
    | 136. | tcp_opt_len_fwd_avg      | Average TCP option length in forward direction                                    | number  |
    | 137. | tcp_opt_cnt_fwd_max      | Maximum number of TCP option in forward direction                                 | #       |
    | 138. | tcp_opt_cnt_fwd_min      | Minimum number of TCP option in forward direction                                 | #       |
    | 139. | tcp_opt_cnt_fwd_avg      | Average number of TCP option in forward direction                                 | #       |
    | 140. | %tcp_opt_sack_fwd        | Ratio of packets with Selective ACK (SACK) in forward direction                   | %       |
    | 141. | %tcp_opt_ts_fwd          | Ratio of packets with timestamp in forward direction                              | %       |
    | 142. | %tcp_opt_tfo_fwd         | Ratio of packets with TCP Fast Open (TFO) in forward direction                    | %       |
    | 143. | %tcp_opt_mptcp_fwd       | Ratio of packets with multipath TCP frame in forward direction                    | %       |
    | 144. | tcp_opt_win_scale_fwd    | TCP window scalier in forward direction                                           | number  |
    | 145. | tcp_opt_mss_fwd          | Maximum segment size in forward direction                                         | number  |
    | 146. | tcp_opt_sack_perm_fwd    | SACK permitted value in forward direction                                         | number  |
    | 147. | tcp_win_fwd_max          | Maximum TCP window in forward direction                                           | number  |
    | 148. | tcp_win_fwd_min          | Minimum TCP window in forward direction                                           | number  |
    | 149. | tcp_win_fwd_avg          | Average TCP window in forward direction                                           | number  |
    | 150. | %tcp_ack_frame_rev       | Ratio of packets with ACK to a previous segment in reverse direction              | %       |
    | 151. | tcp_acked_frame_max_rev  | Maximum number of frame acked at once in reverse direction                        | #       |
    | 152. | tcp_acked_frame_min_rev  | Minimum number of frame acked at once in reverse direction                        | #       |
    | 153. | tcp_acked_frame_avg_rev  | Average number of frame acked at once in reverse direction                        | #       |
    | 154. | tcp_seg_splits_rev_max   | Maximum number of segment splits in reverse direction                             | #       |
    | 155. | tcp_seg_splits_rev_min   | Minimum number of segment splits in reverse direction                             | #       |
    | 156. | tcp_seg_splits_rev_avg   | Average number of segment splits in reverse direction                             | #       |
    | 157. | tcp_ack_rtt_rev_max      | Maximum Round Trip TIme (RTT) to ACK in reverse direction                         | sec     |
    | 158. | tcp_ack_rtt_rev_min      | Minimum Round Trip TIme (RTT) to ACK in reverse direction                         | sec     |
    | 159. | tcp_ack_rtt_rev_avg      | Average Round Trip TIme (RTT) to ACK in reverse direction                         | sec     |
    | 160. | %tcp_nonzero_ack_rev     | Ratio of packets with nonzero ack while ACK flag is not set in reverse direction  | %       |
    | 161. | %tcp_acked_unseen_rev    | Ratio of acked lost packets in reverse direction                                  | %       |
    | 162. | %tcp_pkt_with_bif_rev    | Ratio of packets with bytes in flight in reverse direction                        | %       |
    | 163. | tcp_bif_rev_max          | Maximum bytes in flight in reverse direction                                      | number  |
    | 164. | tcp_bif_rev_min          | Minimum bytes in flight in reverse direction                                      | number  |
    | 165. | tcp_bif_rev_avg          | Average bytes in flight in reverse direction                                      | number  |
    | 166. | %tcp_dup_ack_rev         | Ratio of packets with duplicated ack in reverse direction                         | %       |
    | 167. | %tcp_fast_retran_rev     | Ratio of fast-retransmission in reverse direction                                 | %       |
    | 168. | %tcp_keep_alive_rev      | Ratio of keep-alive in reverse direction                                          | %       |
    | 169. | %tcp_keep_alive_ack_rev  | Ratio of keep-alive ACK in reverse direction                                      | %       |
    | 170. | %tcp_lost_seg_rev        | Ratio of packets missed some previous segments in reverse direction               | %       |
    | 171. | %tcp_out_of_order_rev    | Ratio of out-of-order segments in reverse direction                               | %       |
    | 172. | %tcp_pkt_with_pb_rev     | Ratio of packet sent bytes since last PSH flag in reverse direction               | %       |
    | 173. | tcp_pb_rev_max           | Maximum push bytes right before occurence of PSH flag in reverse direction        | number  |
    | 174. | tcp_pb_rev_min           | Minimum push bytes right before occurence of PSH flag in reverse direction        | number  |
    | 175. | tcp_pb_rev_avg           | Average push bytes right before occurence of PSH flag in reverse direction        | number  |
    | 176. | %tcp_retran_rev          | Ratio of retransmission in reverse direction                                      | %       |
    | 177. | tcp_rto_rev_max          | Maximum retransmission time-out in reverse direction                              | sec     |
    | 178. | tcp_rto_rev_min          | Minimum retransmission time-out in reverse direction                              | sec     |
    | 179. | tcp_rto_rev_avg          | Average retransmission time-out in reverse direction                              | sec     |
    | 180. | %tcp_spur_retran_rev     | Ratio of spurious retransmission in reverse direction                             | %       |
    | 181. | %tcp_win_full_rev        | Ratio of packets with full window in reverse direction                            | %       |
    | 182. | %tcp_win_update_rev      | Ratio of packets with TCP window update in reverse direction                      | %       |
    | 183. | %tcp_zwin_rev            | Ratio of packets with zero window in reverse direction                            | %       |
    | 184. | %tcp_zwin_probe_rev      | Ratio of zero-window-probe in reverse direction                                   | %       |
    | 185. | %tcp_zwin_probe_ack_rev  | Ratio of zero-window-probe ACK in reverse direction                               | %       |
    | 186. | %tcp_FIN_rev             | Ratio of FIN flags in reverse direction                                           | %       |
    | 187. | %tcp_SYN_rev             | Ratio of SYN flags in reverse direction                                           | %       |
    | 188. | %tcp_RST_rev             | Ratio of RST flags in reverse direction                                           | %       |
    | 189. | %tcp_PSH_rev             | Ratio of PSH flags in reverse direction                                           | %       |
    | 190. | %tcp_ACK_rev             | Ratio of ACK flags in reverse direction                                           | %       |
    | 191. | %tcp_URG_rev             | Ratio of URG flags in reverse direction                                           | %       |
    | 192. | %tcp_ECE_rev             | Ratio of ECE flags in reverse direction                                           | %       |
    | 193. | %tcp_CWR_rev             | Ratio of CWR flags in reverse direction                                           | %       |
    | 194. | %tcp_has_opt_rev         | Ratio of packets with TCP options in reverse direction                            | %       |
    | 195. | tcp_opt_len_rev_max      | Maximum TCP option length in reverse direction                                    | number  |
    | 196. | tcp_opt_len_rev_min      | Minimum TCP option length in reverse direction                                    | number  |
    | 197. | tcp_opt_len_rev_avg      | Average TCP option length in reverse direction                                    | number  |
    | 198. | tcp_opt_cnt_rev_max      | Maximum number of TCP option in reverse direction                                 | #       |
    | 199. | tcp_opt_cnt_rev_min      | Minimum number of TCP option in reverse direction                                 | #       |
    | 200. | tcp_opt_cnt_rev_avg      | Average number of TCP option in reverse direction                                 | #       |
    | 201. | %tcp_opt_sack_rev        | Ratio of packets with Selective ACK (SACK) in reverse direction                   | %       |
    | 202. | %tcp_opt_ts_rev          | Ratio of packets with timestamp in reverse direction                              | %       |
    | 203. | %tcp_opt_tfo_rev         | Ratio of packets with TCP Fast Open (TFO) in reverse direction                    | %       |
    | 204. | %tcp_opt_mptcp_rev       | Ratio of packets with multipath TCP frame in reverse direction                    | %       |
    | 205. | tcp_opt_win_scale_rev    | TCP window scalier in reverse direction                                           | number  |
    | 206. | tcp_opt_mss_rev          | Maximum segment size in reverse direction                                         | number  |
    | 207. | tcp_opt_sack_perm_rev    | SACK permitted value in reverse direction                                         | number  |
    | 208. | tcp_win_rev_max          | Maximum TCP window in reverse direction                                           | number  |
    | 209. | tcp_win_rev_min          | Minimum TCP window in reverse direction                                           | number  |
    | 210. | tcp_win_rev_avg          | Average TCP window in reverse direction                                           | number  |
    | 211. | tcp_init_rtt             | Initial Round Trip Time                                                           | sec     |
    +------+--------------------------+-----------------------------------------------------------------------------------+---------+
