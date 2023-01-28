# ARP Packet scanner and sniffer with GoLang (Windows compatible)

CLI command for scanning and monitoring ARP Packets, discover devices, troobleshoot defective devices and more.

## Overview
This is a Golang CLI command easy to use and troobleshoot local networks Link Layer (OSI Model Layer 2).</br>
It contains a manufacturer database to resolve each mac address to the Brand name that belogs.</br>

Inspired from many packet sniffers around github and https://pkg.go.dev/github.com/google/gopacket package.</br>
</br>
Choose between scan OR sniff, scan network every 10 sec or sniff all packets (default "scan")</br>

### Scan
Command will find your active network connection and automatically will scan all IP addresses.</br>
ARP Scan does't guarandee responce from all devices especially the devices that they are in stand by mode thats why it will perform the scan every 10 seconds.</br>

### Sniff
Command will run and listen your active network connection for any ARP packets running around your local network.
It will provide you all the info from the ARP packet traffic around the network.

## Usage
```shell
Usage of C:\git\go-arp-scan-sniff\arpscansniff.exe:
  -filter string
        Packet filter for capture, e.g. arp / udp / tcp and port 80
  -mac string
        Mac address filter, e.g. (3 digits) 30:23:03 / (full mac) 80:ce:62:e8:9b:f5
  -promisc
        Enable promiscuous mode to monitor network,  (default false)
  -type string
        Choose between scan OR sniff, scan network every 10 sec or sniff all packets (default "scan")
```

## Examples and Use cases

* Scan network and get all MAC addresses from active devices.

```shell
./arpscansniff.exe
2023/01/28 12:43:58 Found interface: \Device\NPF_{DF41CF6B-EC4B-46E8-99A7-743F21A641D8}
2023/01/28 12:43:58 Interface IP Address : 192.168.1.100
*
IP     192.168.1.1 -> 30:23:03:6b:d8:cc -> Belkin International Inc.
IP    192.168.1.90 -> 80:ce:62:e8:9b:f5 -> Hewlett Packard
IP   192.168.1.107 -> b4:7c:9c:7d:43:4d -> Amazon Technologies Inc.
IP   192.168.1.116 -> 12:8c:b1:ac:0a:5b -> unknown
IP   192.168.1.136 -> b8:d7:af:ae:4b:6a -> Murata Manufacturing Co., Ltd.
IP   192.168.1.136 -> b8:d7:af:ae:4b:6a -> Murata Manufacturing Co., Ltd.
```
***

* Scan network and get all MAC addresses from active devices that they start with b4:7c:9c (Amazon Technologies Inc.) 

```shell
./arpscansniff.exe -mac b4:7c:9c
2023/01/28 12:57:07 Found interface: \Device\NPF_{DF41CF6B-EC4B-46E8-99A7-743F21A641D8}
2023/01/28 12:57:07 Interface IP Address : 192.168.1.100
*
IP   192.168.1.107 -> b4:7c:9c:7d:43:4d -> Amazon Technologies Inc.
```
***

* Sniff network and log all traffic (Layers 1, 2 & 3) -> 1. Physical, 2. Data link, 3. Network

```shell
./arpscansniff.exe -type sniff
2023/01/28 13:50:46 Found interface: \Device\NPF_{DF41CF6B-EC4B-46E8-99A7-743F21A641D8}
2023/01/28 13:50:46 Interface IP Address : 192.168.1.100

2023/01/28 13:50:46 Start monitoring interface: \Device\NPF_{DF41CF6B-EC4B-46E8-99A7-743F21A641D8}

Packet From : 30:23:03:6b:d8:cc = 66.218.87.15, to : 34:17:eb:c2:03:03, 192.168.1.100
PACKET: 66 bytes, wire length 66 cap length 66 @ 2023-01-28 13:50:49.283964 -0500 EST
- Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..52..] SrcMAC=30:23:03:6b:d8:cc DstMAC=34:17:eb:c2:03:03 EthernetType=IPv4 Length=0}
- Layer 2 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..32..] Version=4 IHL=5 TOS=0 Length=52 Id=40336 Flags=DF FragOffset=0 TTL=48 Protocol=TCP Checksum=20798 SrcIP=66.218.87.15 DstIP=192.168.1.100 Options=[] Padding=[]}
- Layer 3 (32 bytes) = TCP      {Contents=[..32..] Payload=[] SrcPort=443(https) DstPort=17652 Seq=1511366537 Ack=2338396737 DataOffset=8 FIN=false SYN=false RST=false PSH=false ACK=true URG=false ECE=false CWR=false NS=false Window=285 Checksum=60277 Urgent=0 Options=[TCPOption(NOP:), TCPOption(NOP:), TCPOption(SACK: 0x8b611a408b611a41)] Padding=[]}

Packet From : 30:23:03:6b:d8:cc = 66.218.87.15, to : 34:17:eb:c2:03:03, 192.168.1.100
PACKET: 66 bytes, wire length 66 cap length 66 @ 2023-01-28 13:50:49.283964 -0500 EST
- Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..52..] SrcMAC=30:23:03:6b:d8:cc DstMAC=34:17:eb:c2:03:03 EthernetType=IPv4 Length=0}
- Layer 2 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..32..] Version=4 IHL=5 TOS=0 Length=52 Id=40336 Flags=DF FragOffset=0 TTL=48 Protocol=TCP Checksum=20798 SrcIP=66.218.87.15 DstIP=192.168.1.100 Options=[] Padding=[]}
- Layer 3 (32 bytes) = TCP      {Contents=[..32..] Payload=[] SrcPort=443(https) DstPort=17652 Seq=1511366537 Ack=2338396737 DataOffset=8 FIN=false SYN=false RST=false PSH=false ACK=true URG=false ECE=false CWR=false NS=false Window=285 Checksum=60277 Urgent=0 Options=[TCPOption(NOP:), TCPOption(NOP:), TCPOption(SACK: 0x8b611a408b611a41)] Padding=[]}

Packet From : 30:23:03:6b:d8:cc = 192.168.1.1, to : 01:00:5e:7f:ff:fa, 239.255.255.250
PACKET: 60 bytes, wire length 60 cap length 60 @ 2023-01-28 13:50:50.164675 -0500 EST
- Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..46..] SrcMAC=30:23:03:6b:d8:cc DstMAC=01:00:5e:7f:ff:fa EthernetType=IPv4 Length=0}
- Layer 2 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..8..] Version=4 IHL=5 TOS=192 Length=28 Id=59345 Flags= FragOffset=0 TTL=1 Protocol=IGMP Checksum=8107 SrcIP=192.168.1.1 DstIP=239.255.255.250 Options=[] Padding=[]}
- Layer 3 (00 bytes) = IGMP     {Contents=[] Payload=[] Type=IGMP Membership Query MaxResponseTime=10s Checksum=65184 GroupAddress=239.255.255.250 Version=2}
```

* Sniff network and get all ARP packets including devices that are NOT in the same IP Range, perfect for finding lost or misconfigured devices, or devices that they don't get IP Address from DHCP

```shell
./arpscansniff.exe -type sniff -filter arp
2023/01/28 13:46:19 Found interface: \Device\NPF_{DF41CF6B-EC4B-46E8-99A7-743F21A641D8}
2023/01/28 13:46:19 Interface IP Address : 192.168.1.100

2023/01/28 13:46:19 Start monitoring interface: \Device\NPF_{DF41CF6B-EC4B-46E8-99A7-743F21A641D8}
2023/01/28 13:46:19 Filter applied :  arp

ARP Packet From : 34:17:eb:c2:03:03 = 192.168.1.100, to : 30:23:03:6b:d8:cc, 192.168.1.1
PACKET: 42 bytes, wire length 42 cap length 42 @ 2023-01-28 13:46:29.266638 -0500 EST
- Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..28..] SrcMAC=34:17:eb:c2:03:03 DstMAC=30:23:03:6b:d8:cc EthernetType=ARP Length=0}
- Layer 2 (28 bytes) = ARP      {Contents=[..28..] Payload=[] AddrType=Ethernet Protocol=IPv4 HwAddressSize=6 ProtAddressSize=4 Operation=2 SourceHwAddress=[..6..] SourceProtAddress=[192, 168, 1, 100] DstHwAddress=[..6..] DstProtAddress=[192, 168, 1, 1]}
```

* Sniff network and log all traffic at port 80 `-filter "tcp and port 80"` (Layers 1, 2 & 3) -> 1. Physical, 2. Data link, 3. Network

```shell
./arpscansniff.exe -type sniff -filter "tcp and port 80"
2023/01/28 14:12:38 Found interface: \Device\NPF_{DF41CF6B-EC4B-46E8-99A7-743F21A641D8}
2023/01/28 14:12:38 Interface IP Address : 192.168.1.100

2023/01/28 14:12:38 Start monitoring interface: \Device\NPF_{DF41CF6B-EC4B-46E8-99A7-743F21A641D8}
2023/01/28 14:12:38 Filter applied :  tcp and port 80

Packet From : 30:23:03:6b:d8:cc = 89.187.179.132, to : 34:17:eb:c2:03:03, 192.168.1.100
PACKET: 60 bytes, wire length 60 cap length 60 @ 2023-01-28 14:12:48.951066 -0500 EST
- Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..46..] SrcMAC=30:23:03:6b:d8:cc DstMAC=34:17:eb:c2:03:03 EthernetType=IPv4 Length=0}
- Layer 2 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..20..] Version=4 IHL=5 TOS=0 Length=40 Id=3298 Flags=DF FragOffset=0 TTL=55 Protocol=TCP Checksum=26530 SrcIP=89.187.179.132 DstIP=192.168.1.100 Options=[] Padding=[]}
- Layer 3 (20 bytes) = TCP      {Contents=[..20..] Payload=[] SrcPort=80(http) DstPort=36273 Seq=2570368392 Ack=1583498992 DataOffset=5 FIN=false SYN=false RST=false PSH=false ACK=true URG=false ECE=false CWR=false NS=false Window=63966 Checksum=25752 Urgent=0 Options=[] Padding=[]}

Packet From : 34:17:eb:c2:03:03 = 192.168.1.100, to : 30:23:03:6b:d8:cc, 77.234.42.248
PACKET: 54 bytes, wire length 54 cap length 54 @ 2023-01-28 14:12:52.343019 -0500 EST
- Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..40..] SrcMAC=34:17:eb:c2:03:03 DstMAC=30:23:03:6b:d8:cc EthernetType=IPv4 Length=0}
- Layer 2 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..20..] Version=4 IHL=5 TOS=0 Length=40 Id=28675 Flags=DF FragOffset=0 TTL=128 Protocol=TCP Checksum=0 SrcIP=192.168.1.100 DstIP=77.234.42.248 Options=[] Padding=[]}
- Layer 3 (20 bytes) = TCP      {Contents=[..20..] Payload=[] SrcPort=58100 DstPort=80(http) Seq=4190092642 Ack=3338188251 DataOffset=5 FIN=false SYN=false RST=false PSH=false ACK=true URG=false ECE=false CWR=false NS=false Window=62091 Checksum=15113 Urgent=0 Options=[] Padding=[]}

Packet From : 30:23:03:6b:d8:cc = 77.234.42.248, to : 34:17:eb:c2:03:03, 192.168.1.100
PACKET: 60 bytes, wire length 60 cap length 60 @ 2023-01-28 14:12:52.445844 -0500 EST
- Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..46..] SrcMAC=30:23:03:6b:d8:cc DstMAC=34:17:eb:c2:03:03 EthernetType=IPv4 Length=0}
- Layer 2 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..20..] Version=4 IHL=5 TOS=0 Length=40 Id=32593 Flags=DF FragOffset=0 TTL=48 Protocol=TCP Checksum=37008 SrcIP=77.234.42.248 DstIP=192.168.1.100 Options=[] Padding=[]}
- Layer 3 (20 bytes) = TCP      {Contents=[..20..] Payload=[] SrcPort=80(http) DstPort=58100 Seq=3338188341 Ack=4190092948 DataOffset=5 FIN=false SYN=false RST=false PSH=false ACK=true URG=false ECE=false CWR=false NS=false Window=17 Checksum=23565 Urgent=0 Options=[] Padding=[]}

Packet From : 30:23:03:6b:d8:cc = 89.187.179.132, to : 34:17:eb:c2:03:03, 192.168.1.100
PACKET: 60 bytes, wire length 60 cap length 60 @ 2023-01-28 14:12:58.970235 -0500 EST
- Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..46..] SrcMAC=30:23:03:6b:d8:cc DstMAC=34:17:eb:c2:03:03 EthernetType=IPv4 Length=0}
- Layer 2 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..20..] Version=4 IHL=5 TOS=0 Length=40 Id=3299 Flags=DF FragOffset=0 TTL=55 Protocol=TCP Checksum=26529 SrcIP=89.187.179.132 DstIP=192.168.1.100 Options=[] Padding=[]}
- Layer 3 (20 bytes) = TCP      {Contents=[..20..] Payload=[] SrcPort=80(http) DstPort=36273 Seq=2570368392 Ack=1583498992 DataOffset=5 FIN=false SYN=false RST=false PSH=false ACK=true URG=false ECE=false CWR=false NS=false Window=63966 Checksum=25752 Urgent=0 Options=[] Padding=[]}
```


</br>