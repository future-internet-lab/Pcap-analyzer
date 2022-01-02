import argparse
import os
import sys
from scapy.utils import PcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
#from scapy.all import *
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

count_pkt = []
def process_pcap(file_name, mode="tcp", unit="packet/s"):
    print('Opening {}...'.format(file_name))
    count = 0
    count_packet = 0
    step = 0
    current_time = 0
    list_packet_timestamp = []
    Timestamp_Flow = {}

    for pkt_data in PcapReader(file_name):
        count += 1
        pkt_timestamp = int(pkt_data.time)
        if len(str(pkt_timestamp)) != 10:   # Epoch timestamp must be 10 digits
            pkt_timestamp = int(pkt_timestamp *(10**-3))
        if count == 1:
            current_time = pkt_timestamp

        if 'type' not in pkt_data.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue
        if pkt_data.type != 0x0800:  # disregard non-IPv4 packets
            continue

        if unit == "packet/s":
            step = 1
        else:
            step = pkt_data.len + 14

        if mode == "icmp":
            if pkt_data.proto == 1:
                count_packet += step
                timestamp = pkt_timestamp
                if current_time != timestamp:
                    if timestamp - current_time > 1:
                        for i in range(current_time + 1, timestamp):
                            list_packet_timestamp.append([i, 0])
                    current_time = timestamp
                    if current_time != 0:
                        list_packet_timestamp.append([current_time, count_packet])
                        count_packet = 0

        if mode == "tcp":
            ip_pkt = pkt_data.getlayer(IP)
            tcp_pkt = pkt_data.getlayer(TCP)
            if pkt_data.proto == 6 and tcp_pkt.flags=="S":
                count_packet += step
                timestamp = pkt_timestamp
                #IPport = (ip_pkt.src) + ':' + (tcp_pkt.sport) # IPaddress:port
                #Timestamp_Flow[IPport] = pkt_timestamp
                try:
                    Timestamp_Flow[pkt_timestamp] += step
                except KeyError:
                    Timestamp_Flow[pkt_timestamp] = step
                
                if current_time != timestamp:
                    if timestamp - current_time > 1:
                        for i in range(current_time + 1, timestamp):
                            list_packet_timestamp.append([i, 0])

                    current_time = timestamp
                    if current_time != 0:
                        list_packet_timestamp.append([current_time, count_packet])
                        count_packet = 0

        if count % 10000 == 0:
            print(count)

    TF = pd.DataFrame.from_dict(Timestamp_Flow, orient='index', columns = ['timestamp'])

    TF.to_csv("./save_table/Timestamp_ac_" + file_name.split('.')[0] + '_' + name.replace(' ','') + ".csv", index=True)

    list_packet_timestamp = np.array(list_packet_timestamp)
    count_pkt.append(count)
    print("processing file {} <{} packets> done".format(file_name, count))
    #pd.DataFrame(data=list_packet_timestamp).to_csv("./save_table/" + file_name + ".csv", index=None)
    return list_packet_timestamp


def plot_graph(list_packetin_timestamp, list_packetout_timestamp, file_name, unit="packet/s"):
    # print(list_packetin_timestamp)
    # print(list_packetout_timestamp)

    # Save table file to csv
    pd.DataFrame(data=list_packetin_timestamp).to_csv("./save_table/ac_in_" + name.replace(' ','') + ".csv", index=None)
    pd.DataFrame(data=list_packetout_timestamp).to_csv("./save_table/ac_out_" + name.replace(' ','') + ".csv", index=None)

    # get min timestamp of 2 tables
    min_timestamp = 0
    if np.min(list_packetin_timestamp[:, 0]) > np.min(list_packetout_timestamp[:, 0]):
        min_timestamp = np.min(list_packetout_timestamp[:, 0])
    else:
        min_timestamp = np.min(list_packetin_timestamp[:, 0])

    list_packetin_timestamp[:, 0] -= min_timestamp
    list_packetout_timestamp[:, 0] -= min_timestamp

    plt.figure()
    plt.plot(list_packetin_timestamp[:, 0], list_packetin_timestamp[:, 1], label="interface a", linewidth=3.5)
    plt.plot(list_packetout_timestamp[:, 0], list_packetout_timestamp[:, 1], label="interface c", linewidth=1.8)
    plt.xlabel("timestamp")
    plt.ylabel(unit)
    plt.minorticks_on()
    plt.title(file_name+"\n"+"interface_a="+str(count_pkt[0])+"  interface_c="+str(count_pkt[1]))
    plt.legend()
    plt.savefig(file_name)
    plt.show()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap1', metavar='<file 1 name>', help='file 1 to parse', required=True)
    parser.add_argument('--pcap2', metavar='<file 2 name>', help='file 2 to parse', required=True)
    parser.add_argument('--mode', metavar='<mode icmp or tcp>', help='using for icmp or tcp packet', required=False)
    parser.add_argument('--unit', metavar='<packet/s or bytes/s>', help='setting unit for y axis', required=False)
    parser.add_argument('--name', metavar='<desired title>', help='input your desired title', required=True)

    args = parser.parse_args()

    file_name_1 = args.pcap1
    file_name_2 = args.pcap2
    mode = args.mode
    unit = args.unit
    name = args.name
    for file_name in [file_name_1, file_name_2]:
        if not os.path.isfile(file_name):
            print('"{}" does not exist'.format(file_name))
            sys.exit(-1)

    list_packet_1_timestamp = process_pcap(file_name_1, mode, unit)
    list_packet_2_timestamp = process_pcap(file_name_2, mode, unit)

    plot_graph(list_packet_1_timestamp, list_packet_2_timestamp, name, unit)
    #file_name_1[0:-5] + "_and_c"

    sys.exit(0)
