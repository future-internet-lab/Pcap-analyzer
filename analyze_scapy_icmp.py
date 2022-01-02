#############################################################################
########### Analyze OpenFlow header by parsing packet payload ###############
#############################################################################
############################# Anh Khoa Dang #################################
#############################################################################
########## V2: Adding Timestamp DataFrame for each IP address ###############
#############################################################################
import argparse
import os
import sys
import binascii
import re      #Regular Expression
#import time

#from matplotlib.ticker import MultipleLocator, FormatStrFormatter
from scapy.utils import PcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
#from scapy.all import *
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
#from scapy.contrib.openflow import OFPMatch, OFPTPacketIn,OFPTPacketOut, OFPTFlowMod
#from scapy.contrib.openflow3 import OFPMatch, OFPTPacketIn, OFPTPacketOut, OFPTFlowMod

count_pkt = []
Timestamp_PacketIn, Timestamp_FlowMod = {}, {} #V2: Dictionary contains timestamp of specific OpenFlow packet

def process_pcap(file_name):
    print('Opening {}...'.format(file_name))
    count = 0
    count_packet_in, count_packet_out, count_flow_mod = 0, 0, 0
    current_time_packetin, current_time_packetout, current_time_flowmod = 0, 0, 0
    count_flow_mod_ts, count_packet_in_ts, count_packet_out_ts = 0, 0, 0 # Timestamp purpose
    list_packetin_timestamp, list_flowmod_timestamp = [], []
    #list_packetout_timestamp = []

    for pkt_data in PcapReader(file_name):
        count += 1
        if pkt_data.type != 0x0800:  # disregard non-IPv4 packets
            continue
        if pkt_data.proto != 6:      # Ignore non-TCP packet
            continue
        pkt_timestamp = int(pkt_data.time)
        if len(str(pkt_timestamp)) != 10:   # Epoch timestamp must be 10 digits
            pkt_timestamp = int(pkt_timestamp *(10**-3))

        tcp_payload = pkt_data.lastlayer()  # Get payload of TCP layer
        payload = binascii.hexlify(bytes(tcp_payload)) # Convert to heximal
                                                                  # ac100164 // IP 172.16.1.100  0a000002      # 0913 // port 2323
        packet_in = re.findall(b'(010a)(.{4})(00000000ffffffff)(.{8})(0000)(.{52})(.{8})(0a000002)(0800)', payload)
        flow_mod = re.findall(b'(010e)(.{68})(.{8})(0a000002)(.{4})(.{20})(000000000000....ffffffff)', payload)
        packet_out = 0 #len(re.findall(b'(010d)(.{104})(ac100164)', payload))
        has_packet_in, has_packet_out, has_flow_mod = False, False, False
        if packet_in:
            len_packet_in = len(packet_in)
            count_packet_in += len_packet_in
            if count_packet_in / len_packet_in == 1:
                current_time_packetin = pkt_timestamp
            count_packet_in_ts += len_packet_in
            for i in range(len_packet_in):
                IPport = (packet_in[i][6]).decode() # IPaddress:port
                Timestamp_PacketIn[IPport] = pkt_timestamp
            has_packet_in = True
        if flow_mod:
            len_flow_mod = len(flow_mod)
            count_flow_mod += len_flow_mod
            if count_flow_mod / len_flow_mod == 1:
                current_time_flowmod = pkt_timestamp
            count_flow_mod_ts += len_flow_mod
            for i in range(len_flow_mod):
                IPport = (flow_mod[i][2]).decode() # IPaddress:port
                Timestamp_FlowMod[IPport] = pkt_timestamp
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
            print(f"Packets processed: {count}")
    
    print('<{}> contains {} packets ({} packet in, {} packet out, {} flow mod)'
            .format(file_name, count, count_packet_in, count_packet_out, count_flow_mod))
    # V2:
    PI = pd.DataFrame.from_dict(Timestamp_PacketIn, orient='index', columns = ['PacketIn'])
    FM = pd.DataFrame.from_dict(Timestamp_FlowMod, orient='index', columns = ['FlowMod'])   
    Timestamp_DF = PI.merge(FM, left_index=True, right_index=True)
    Timestamp_DF.to_csv("./save_table/Timestamp_Table_" + file_name.strip('.pcap') + ".csv", index=True)

    count_pkt.append(count_packet_in)
    count_pkt.append(count_flow_mod)
    plot_graph(np.array(list_packetin_timestamp), np.array(list_flowmod_timestamp), file_name)

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
    pd.DataFrame(data=list_packetin_timestamp).to_csv("./save_table/b_flow_in_" + file_name.strip('.pcap') + ".csv", index=None)
    pd.DataFrame(data=list_flowmod_timestamp).to_csv("./save_table/b_flow_out_" + file_name.strip('.pcap') + ".csv", index=None)

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
    plt.title(name + "\n" + "packet_in="+str(count_pkt[0])+"  flow_mod="+str(count_pkt[1]))
    plt.legend()
    plt.savefig(name)
    plt.show()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>', help='pcap file to parse', required=True)
    parser.add_argument('--name', metavar='<desired title of graph>', help='desired title of graph', required=True)
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
