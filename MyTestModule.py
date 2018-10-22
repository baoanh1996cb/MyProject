import time
from builtins import set
import platform
import pyshark
import glob
import os
from threading import Thread
import threading
import platform

class Protocol:

    protocol = {
        "tcp" : "1",
        "icmp" : "1",
        "udp" : "1",
    }


class HandlePcap:

    # Return "" if value equal None
    def cvNonetoStr(self, var):
        if var == None:
            return ""
        else:
            return var

    # Check has attribute
    def check_hasattr(self, parent, child):
        if hasattr(parent, child):
            return True;
        return False;

    # 1- Get Source ip
    def get_src_ip(self, packet, protocol):
        src_ip = ""
        if self.check_hasattr(packet, "ip"):
            src_ip = packet.ip.src_host
        return str(src_ip)

    # 2- Get Destination ip
    def get_dst_ip(self, packet, protocol):
        dst_ip = ""
        if self.check_hasattr(packet, "ip"):
            dst_ip = packet.ip.dst_host
        return str(dst_ip)

    # 3 - Get Source port
    def get_src_port(self, packet, protocol):
        src_port = ""
        if self.check_hasattr(packet, protocol):
            src_port = packet[protocol].srcport
        return str(src_port)

    # 4 - Get Destination port
    def get_dst_port(self, packet, protocol):
        dst_port = ""
        if self.check_hasattr(packet, protocol):
            dst_port = packet[protocol].dstport
        return str(dst_port)

    # 5- Get protocol
    def get_protocol(self, packet):
        protocol = "other"
        protocolDic = Protocol.protocol
        if self.check_hasattr(packet, "frame_info"):
            split = str(packet.frame_info.protocols).split(":")
            i = 0
            while i < len(split):
                protocol = protocolDic.get(split[i])
                if protocol != None:
                    protocol = split[i]
                    break
                i += 1
        return protocol

    # 6 - Get number of packets to dst_ip per protocol
    def get_packets(self, protocol, dst_ip, pcap):
        num_packet = 0
        for packet in pcap:
            if protocol == self.get_protocol(packet) and dst_ip == self.get_dst_ip(packet, protocol):
                num_packet += 1
        return str(num_packet)

    # 7 - Get number of bytes to dst_ip per protocol
    def get_bytes(self, protocol, dst_ip, pcap):
        bytes = 0
        for packet in pcap:
            if protocol == self.get_protocol(packet) and dst_ip == self.get_dst_ip(packet, protocol):
                bytes += int(packet.frame_info.len)
        return str(bytes)

    # 8 - Count same src_ip, src_port  to difference dst_ip, dst_port
    def get_ssrc_diff_dst(self, protocol, src_ip, src_port, dst_ip, dst_port, pcap):
        count = 0
        for packet in pcap:
            if src_ip == self.get_src_ip(packet, protocol) and src_port == self.get_src_port(packet, protocol)\
                and (dst_ip != self.get_dst_ip(packet, protocol) or dst_port != self.get_dst_port(packet, protocol)):
                count += 1
        return str(count)

    # 9 - Count diff src_ip, src_port  to same dst_ip, dst_port
    def get_sdst_diff_src(self, protocol, src_ip, src_port, dst_ip, dst_port, pcap):
        count = 0
        for packet in pcap:
            if dst_ip == self.get_dst_ip(packet, protocol) and dst_port == self.get_dst_port(packet, protocol)\
                and (src_ip != self.get_src_ip(packet, protocol) or src_port != self.get_src_port(packet, protocol)):
                count += 1
        return str(count)

    # 10 - get Land
    def get_land(self, protocol, src_ip, src_port, dst_ip, dst_port, pcap):
        count = 0
        for packet in pcap:
            if src_ip == self.get_src_ip(packet, protocol) and src_port == self.get_src_port(packet, protocol)\
                and dst_ip == self.get_dst_ip(packet, protocol) and dst_port == self.get_dst_port(packet, protocol):
                count += 1
        return str(count)

    def get_extract_path(self, src_path):
        list = []
        fileExtract = ""
        if platform.system() == "Windows":
            list = src_path.split("\\")
            fileExtract = os.getcwd() + "\\DatasetTest\\" + list[-1].replace("pcap","csv")
        elif platform.system() == "Linux":
            list = src_path.split("/")
            fileExtract = os.getcwd() + "/DatasetTest/" + list[-1].replace("pcap","csv")
        else:
            print("Sorry, we do not support your system")
        return fileExtract


    def getFeature(self, src_path):

        FILEPATH = src_path
        FILE_EXTRACT_PATH = self.get_extract_path(FILEPATH)
        pcap = pyshark.FileCapture(FILEPATH)
        pcap.load_packets()
        featureTotal = ""
        mySet = set()
        if len(pcap) > 0:
            for packet in pcap:
                featureStr = ""
                protocol = self.get_protocol(packet)
                src_ip = self.get_src_ip(packet, protocol)
                dst_ip = self.get_dst_ip(packet, protocol)
                src_port = self.get_src_port(packet, protocol)
                dst_port = self.get_dst_port(packet, protocol)
                num_packets = self.get_packets(protocol, dst_ip, pcap)
                num_bytes = self.get_bytes(protocol, dst_ip, pcap)
                num_ssrc_diff_dst = self.get_ssrc_diff_dst(protocol, src_ip, src_port, dst_ip, dst_port, pcap)
                num_sdst_diff_src = self.get_sdst_diff_src(protocol, src_ip, src_port, dst_ip, dst_port, pcap)
                num_land = self.get_land(protocol, src_ip, src_port, dst_ip, dst_port, pcap)
                featureStr += protocol + ","
                featureStr += src_ip + ","
                featureStr += dst_ip + ","
                featureStr += src_port + ","
                featureStr += dst_port + ","
                featureStr += num_packets + ","
                featureStr += num_bytes + ","
                featureStr += num_ssrc_diff_dst + ","
                featureStr += num_sdst_diff_src + ","
                featureStr += num_land + "\n"
                if featureStr not in mySet:
                    mySet.add(featureStr)
                    featureTotal += featureStr
            f = open(FILE_EXTRACT_PATH, "w+")
            f.write(featureTotal)
            f.close()
            pcap.close()

def featureExtract():

    handlePcap = HandlePcap()
    # LASTFILE = "/home/baoanh/Desktop/Project/PcapCapture/01-telnet.pcap"
    LASTFILE = ""
    curDirWorking = ""
    if platform.system() == "Windows":
        curDirWorking = os.getcwd()
        LASTFILE = curDirWorking + "\\PcapCapture\\01-telnet.pcap"
    elif platform.system() == "Linux":
        curDirWorking = os.getcwd()
        LASTFILE = curDirWorking + "/PcapCapture/01-telnet.pcap"
    else:
        print("Sorry, we do not support your system")
    thread = threading.Thread(target=handlePcap.getFeature(LASTFILE))
    # thread = Thread(target=handlePcap.getFeature, args=(LASTFILE,))
    # thread.start()
    # time.sleep(2);
    # handlePcap.getFeature("Im Bao Anh")
    # while True:
    #     # * means all if need specific format then *.pcap
    #     list_of_files = glob.glob("D:\\University\\Fall2018\\Capstone Project\\Tool\\Python\Test\\*")
    #     if len(list_of_files) != 0:
    #         latest_file = max(list_of_files, key=os.path.getctime)
    #         if LASTFILE != latest_file:
    #             LASTFILE = latest_file
    #             time.sleep(2)
    #             thread = Thread(target=handlePcap.getFeature, args=(LASTFILE,))
    #             thread.start()
    #
    #     time.sleep(0.1)

