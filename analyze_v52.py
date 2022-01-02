#PCAP analyzing using pyshark module by Khoa
#Usage: Count packetin, packetout, flowmod

import argparse
import os
import sys
import pyshark

from matplotlib.ticker import MultipleLocator, FormatStrFormatter
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
count_pkt = []
def process_pcap(file_name, _filter = None):
    print('Opening {}...'.format(file_name))
    pcap = pyshark.FileCapture(file_name, display_filter = _filter)
    pcap.set_debug()
    #############################################################################################
    count = 0 #Count number of packets in pcap
    count_packet_in, count_packet_out, count_flow_mod = 0, 0, 0
    count_flow_mod_ts, count_packet_in_ts, count_packet_out_ts = 0, 0, 0 #timestamp purpose
    current_time_packetin, current_time_packetout, current_time_flowmod = 0, 0, 0
    list_packetin_timestamp, list_flowmod_timestamp = [], []
    #list_AttributeError = []
    #############################################################################################

    for pkt in pcap: #loop each packet in pcap file
        count += 1
        pkt_timestamp = int(float(pkt.sniff_timestamp)) #packet timestamp
        if count == 1:
            current_time_packetin = 0
            #current_time_packetout = pkt_timestamp
            current_time_flowmod = 0
    #############################################################################################
    # Layer process
    #############################################################################################
        has_packet_in, has_packet_out, has_flow_mod = False, False, False
        num_of_layers = len(pkt.get_multiple_layers('openflow_v1')) #Number of openflow layers
        num_layers = len(pkt.layers) #Number of packet layers
        if num_of_layers:
	        for i in range(3, num_layers):
	            try:
	                of_type = pkt[i].openflow_1_0_type  # PACKETIN:10  PACKETOUT:13  FLOWMOD:14
	            except AttributeError:
	                #list_AttributeError.append(count)
	                continue
	            else:
	                if int(of_type) == 10:
	                    count_packet_in += 1
	                    if count_packet_in == 1:
	                        current_time_packetin = pkt_timestamp
	                    count_packet_in_ts += 1
	                    has_packet_in = True
	                elif int(of_type) == 13:
	                    count_packet_out += 1
	                    if count_packet_out == 1:
	                        current_time_packetout = pkt_timestamp
	                    count_packet_out_ts += 1
	                    has_packet_out = True
	                elif int(of_type) == 14:
	                    count_flow_mod += 1
	                    if count_flow_mod == 1:
	                        current_time_flowmod = pkt_timestamp
	                    count_flow_mod_ts += 1
	                    has_flow_mod = True
    #############################################################################################
    # Timestamp process
    #############################################################################################
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

        if count % 1 == 0: #View packet process
            print('Packets Processed: {}'.format(count), end = "\r")
    print('<{}> contains {} packets ({} packet in, {} packet out, {} flow mod)'
            .format(file_name, count, count_packet_in, count_packet_out, count_flow_mod))
    count_pkt.append(count_packet_in)
    count_pkt.append(count_flow_mod)
    #unusual = list(set(list_AttributeError))
    #print('Unusual packet: {} {}'.format(len(unusual), unusual))
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
    majorLocator = MultipleLocator(20)
    majorFormatter = FormatStrFormatter("%d")
    minorLocator = MultipleLocator(6)

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
    parser.add_argument('--display_filter', metavar='<display filter>', help='wireshark display filter', required=False)
    parser.add_argument('--name', metavar='<desired name>', help='desired title of graph', required=True)
    args = parser.parse_args()

    file_name = args.pcap
    _filter = args.display_filter
    name = args.name
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name))
        sys.exit(-1)

    process_pcap(file_name, _filter)
    sys.exit(0)
