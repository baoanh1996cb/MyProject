SET dir=%cd%
start C:\"Program Files"\Wireshark\tshark.exe -b duration:2 -w "%dir%\PcapCapture\temp.pcap"