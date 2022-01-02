#############################################################################
########### Analyze OpenFlow header by parsing packet payload ###############
#############################################################################
############################# Anh Khoa Dang #################################
#############################################################################
import argparse
import os
import sys
import binascii
import re
#import time

#from matplotlib.ticker import MultipleLocator, FormatStrFormatter
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
#from scapy.all import *
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
#from scapy.contrib.openflow import OFPMatch, OFPTPacketIn,OFPTPacketOut, OFPTFlowMod
#from scapy.contrib.openflow3 import OFPMatch, OFPTPacketIn, OFPTPacketOut, OFPTFlowMod

count_pkt = []
def process_pcap(file_name):
    print('Opening {}...'.format(file_name))
    count = 0
    count_packet_in, count_packet_out, count_flow_mod = 0, 0, 0
    current_time_packetin, current_time_packetout, current_time_flowmod = 0, 0, 0
    count_flow_mod_ts, count_packet_in_ts, count_packet_out_ts = 0, 0, 0 # Timestamp purpose
    list_packetin_timestamp, list_flowmod_timestamp = [], []
    #list_packetout_timestamp = []

    for (pkt_data, pkt_metadata) in RawPcapReader(file_name):
        count += 1

        try:
        	pkt_timestamp = ((pkt_metadata.tshigh << 32) | pkt_metadata.tslow) // pkt_metadata.tsresol # tshark timestamp
            if len(str(pkt_timestamp)) != 10:
            	pkt_timestamp = int(pkt_timestamp*(10**-3)) # tshark pcap timestamp
        except AttributeError:
            pkt_timestamp = pkt_metadata.sec # tcpdump or netsniff-ng timestamp

        if count == 1:
            current_time_packetin = 0
            current_time_packetout = 0
            current_time_flowmod = 0          
        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue
        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue
        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto != 6:
            # Ignore non-TCP packet
            continue
        tcp_pkt = ip_pkt[TCP]

        payload = binascii.hexlify(bytes(tcp_pkt.payload))

        # 0x7F, 0x00, 0x00, 0x01 //IP 127.0.0.1
        # 0x0A, 0x00, 0x00, 0x02 //IP 10.0.0.2 (.{8})(0000) (0a000002|ac100164|00000000)
        # 0xAC, 0x10, 0x01, 0x64 //IP 172.16.1.100

        packet_in = len(re.findall(b'(010a)(.{4})(00000000ffffffff)(.{8})(0000)(.{60})(........)', payload))
        flow_mod = len(re.findall(b'(010e)(.{76})(........)(.{24})(000000000000....ffffffff)', payload))
        packet_out = len(re.findall(b'(010d)(.{104})(ac100164|0a000002)', payload))

        has_packet_in, has_packet_out, has_flow_mod = False, False, False
        if packet_in:
            count_packet_in += packet_in
            if count_packet_in == 1:
                current_time_packetin = pkt_timestamp
            count_packet_in_ts += packet_in
            has_packet_in = True
        if flow_mod:
            count_flow_mod += flow_mod
            if count_flow_mod == 1:
                current_time_flowmod = pkt_timestamp
            count_flow_mod_ts += flow_mod
            has_flow_mod = True
        if packet_out:
            count_packet_out += packet_out
            #    if count_packet_out == 1:
            #        current_time_packetout = pkt_timestamp
            #    count_packet_out_ts += packet_out
            #    has_packet_out = True

    ################### Timestamp process ##################################################
        if has_packet_in is True:
            time_stamp = pkt_timestamp
            if current_time_packetin != time_stamp:
                if time_stamp - current_time_packetin > 1:
                    for i in range(current_time_packetin+1, time_stamp):
                        list_packetin_timestamp.append([i,0])

                current_time_packetin = time_stamp
                if current_time_packetin != 0:
                    list_packetin_timestamp.append([current_time_packetin, count_packet_in_ts])
                    count_packet_in_ts = 0

        # if has_packet_out is True:
        #     timestamp = pkt_timestamp
        #     if current_time_packetout != timestamp:
        #         # if (timestamp - current_time_packetout > 1) and current_time_packetout != 0:
        #         #     for i in range(current_time_packetout+1, timestamp):
        #         #         list_flowmod_timestamp.append([i, count_packet_out-1])

        #         current_time_packetout = timestamp
        #         if current_time_packetout != 0:
        #             list_flowmod_timestamp.append([current_time_packetout, count_packet_out])

        if has_flow_mod is True:
            time_stamp = pkt_timestamp
            if current_time_flowmod != time_stamp:
                if ((time_stamp - current_time_flowmod) > 1) and current_time_flowmod != 0:
                    for i in range(current_time_flowmod+1, time_stamp):
                        list_flowmod_timestamp.append([i,0])

                current_time_flowmod = time_stamp
                if current_time_flowmod != 0:
                    list_flowmod_timestamp.append([current_time_flowmod, count_flow_mod_ts])
                    count_flow_mod_ts = 0

        if count % 10000 == 0:
            print("Packets processed: {}".format(count))
    
    print('<{}> contains {} packets ({} packet in, {} packet out, {} flow mod)'
            .format(file_name, count, count_packet_in, count_packet_out, count_flow_mod))
    count_pkt.append(count_packet_in)
    count_pkt.append(count_flow_mod)
    plot_graph(np.array(list_packetin_timestamp), np.array(list_flowmod_timestamp), name)

def plot_graph(list_packetin_timestamp, list_flowmod_timestamp, file_name):

    # get min timestamp of 2 tables
    #min_timestamp = 0
    if np.min(list_packetin_timestamp[:, 0]) > np.min(list_flowmod_timestamp[:, 0]):
        min_timestamp = np.min(list_flowmod_timestamp[:, 0])
    else:
        min_timestamp = np.min(list_packetin_timestamp[:, 0])
    list_packetin_timestamp[:, 0] -= min_timestamp
    list_flowmod_timestamp[:, 0] -= min_timestamp

    # Save table file to csv
    pd.DataFrame(data=list_packetin_timestamp).to_csv("./save_table/b_flow_in_" + file_name + ".csv", index=None)
    pd.DataFrame(data=list_flowmod_timestamp).to_csv("./save_table/b_flow_out_" + file_name + ".csv", index=None)

    print(list_packetin_timestamp)
    print(list_flowmod_timestamp)
    # initial ticks and sub sticks for graph
    #majorLocator = MultipleLocator(20)
    #majorFormatter = FormatStrFormatter("%d")
    #minorLocator = MultipleLocator(6)

    plt.figure()
    plt.plot(list_packetin_timestamp[:, 0], list_packetin_timestamp[:, 1], c="g", label="flow_in", linewidth=3.5)
    plt.plot(list_flowmod_timestamp[:, 0], list_flowmod_timestamp[:, 1], c="r", label="flow_out", linewidth=1.8)
    # plt.axes().xaxis.set_major_locator(majorLocator)
    # plt.axes().xaxis.set_major_formatter(majorFormatter)
    # plt.axes().xaxis.set_minor_locator(minorLocator)
    plt.minorticks_on()
    plt.xlabel("timestamp (s)")
    plt.ylabel("packets/s")
    plt.title(file_name + "\n" + "packet_in="+str(count_pkt[0])+"  flow_mod="+str(count_pkt[1]))
    plt.legend()
    plt.savefig(file_name)
    plt.show()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>', help='pcap file to parse', required=True)
    parser.add_argument('--name', metavar='<desired name>', help='desired title of graph', required=True)
    args = parser.parse_args()

    file_name = args.pcap
    name = args.name
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name))
        sys.exit(-1)

    #start_time = time.time()
    process_pcap(file_name)
    #print("--- %s seconds ---" % (time.time() - start_time))
    sys.exit(0)
