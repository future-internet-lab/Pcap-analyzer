#############################################################################
########### Analyze OpenFlow header by parsing packet payload ###############
#############################################################################
############################# Anh Khoa Dang #################################
#############################################################################
import argparse
import os
import sys
#from matplotlib.ticker import MultipleLocator, FormatStrFormatter
from scapy.utils import PcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP
#from scapy.all import *
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

count_pkt = []
def process_pcap(file_name):
    print('Opening {}...'.format(file_name))
    count = 0
    count_request, count_reply = 0, 0
    current_time_request, current_time_reply = 0, 0
    count_request_ts, count_reply_ts = 0, 0 # Timestamp purpose
    list_request_timestamp, list_reply_timestamp = [], []
    #list_ack_timestamp = []

    for pkt_data in PcapReader(file_name):
        count += 1
        #print(count)
        if pkt_data.type != 0x0800:
            # disregard non-IPv4 packets
            continue
        if pkt_data.proto != 1:
            # Ignore non-ICMP packet
            continue

        pkt_timestamp = int(pkt_data.time)
        if len(str(pkt_timestamp)) != 10: # Epoch timestamp must be 10 digits
            pkt_timestamp = int(pkt_timestamp *(10**-3))

        icmp = pkt_data.getlayer(ICMP)
        icmp_type = icmp.type
        # 8 = echo-request, 0 = echo-reply

        has_request, has_reply = False, False
        if icmp_type == 8:
            count_request += 1
            if count_request == 1:
                current_time_request = pkt_timestamp
            count_request_ts += 1
            has_request = True
        if icmp_type == 0:
            count_reply += 1
            if count_reply == 1:
                current_time_reply = pkt_timestamp
            count_reply_ts += 1
            has_reply = True
    ################### Timestamp process ##################################################
        if has_request is True:
            time_stamp = pkt_timestamp
            if current_time_request != time_stamp:
                if time_stamp - current_time_request > 1:
                    for i in range(current_time_request+1, time_stamp):
                        list_request_timestamp.append([i,0])

                current_time_request = time_stamp
                if current_time_request != 0:
                    list_request_timestamp.append([current_time_request, count_request_ts])
                    count_request_ts = 0

        # if has_packet_out is True:
        #     timestamp = pkt_timestamp
        #     if current_time_packetout != timestamp:
        #         # if (timestamp - current_time_packetout > 1) and current_time_packetout != 0:
        #         #     for i in range(current_time_packetout+1, timestamp):
        #         #         list_flowmod_timestamp.append([i, count_packet_out-1])

        #         current_time_packetout = timestamp
        #         if current_time_packetout != 0:
        #             list_flowmod_timestamp.append([current_time_packetout, count_packet_out])

        if has_reply is True:
            time_stamp = pkt_timestamp
            if current_time_reply != time_stamp:
                if ((time_stamp - current_time_reply) > 1) and current_time_reply != 0:
                    for i in range(current_time_reply+1, time_stamp):
                        list_reply_timestamp.append([i,0])

                current_time_reply = time_stamp
                if current_time_reply != 0:
                    list_reply_timestamp.append([current_time_reply, count_reply_ts])
                    count_reply_ts = 0

        if count % 10000 == 0:
            print("Packets processed: {}".format(count))
    
    print('<{}> contains {} packets ({} echo-request, {} echo-reply)'
            .format(file_name, count, count_request, count_reply))
    count_pkt.append(count_request)
    count_pkt.append(count_reply)
    plot_graph(np.array(list_request_timestamp), np.array(list_reply_timestamp), name)

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
    plt.plot(list_packetin_timestamp[:, 0], list_packetin_timestamp[:, 1], c="g", label="echo-request", linewidth=3.5)
    plt.plot(list_flowmod_timestamp[:, 0], list_flowmod_timestamp[:, 1], c="r", label="echo-reply", linewidth=1.8)
    # plt.axes().xaxis.set_major_locator(majorLocator)
    # plt.axes().xaxis.set_major_formatter(majorFormatter)
    # plt.axes().xaxis.set_minor_locator(minorLocator)
    plt.minorticks_on()
    plt.xlabel("Time (s)")
    plt.ylabel("packets/s")
    plt.title(file_name + "\n" + "echo-request="+str(count_pkt[0])+"  echo-reply="+str(count_pkt[1]))
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
