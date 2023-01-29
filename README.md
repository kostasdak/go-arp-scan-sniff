# ARP packet scanner and sniffer with GoLang for Windows

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
 ./arpscansniff.exe --help
Usage of C:\git\go-arp-scan-sniff\arpscansniff.exe:
  -filter string
        Packet filter for capture, e.g. arp / all (default "arp")
  -mac string
        Mac address filter, e.g. (3 digits) 30:23:03 / (full addr) 80:ce:62:e8:9b:f5
  -promisc
        Enable/Disable promiscuous mode to monitor network (default true)
  -type string
        Choose between scan / sniff, scan network every 10 sec or sniff all packets (default "scan")
```

## Examples and Use cases

* Scan network and get all MAC addresses from active devices.

```shell
`./arpscansniff.exe`

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

* Sniff network and log all traffic (Layers 1, 2, 3 & 4) -> 1. Physical, 2. Data link, 3. Network & 4. Transport

```shell
./arpscansniff.exe -type sniff -filter all
2023/01/28 21:46:04 Found interface: \Device\NPF_{DF41CF6B-EC4B-46E8-99A7-743F21A641D8}
2023/01/28 21:46:04 Interface IP Address : 192.168.1.100

2023/01/28 21:46:04 Start monitoring interface: \Device\NPF_{DF41CF6B-EC4B-46E8-99A7-743F21A641D8}

Layer 3 packet From : 30:23:03:6b:d8:cc = 192.168.1.1, to : 01:00:5e:7f:ff:fa, 239.255.255.250
PACKET: 60 bytes, wire length 60 cap length 60 @ 2023-01-28 21:46:09.868226 -0500 EST
- Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..46..] SrcMAC=30:23:03:6b:d8:cc DstMAC=01:00:5e:7f:ff:fa EthernetType=IPv4 Length=0}
- Layer 2 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..8..] Version=4 IHL=5 TOS=192 Length=28 Id=44432 Flags= FragOffset=0 TTL=1 Protocol=IGMP Checksum=23020 SrcIP=192.168.1.1 DstIP=239.255.255.250 Options=[] Padding=[]}
- Layer 3 (00 bytes) = IGMP     {Contents=[] Payload=[] Type=IGMP Membership Query MaxResponseTime=10s Checksum=65184 GroupAddress=239.255.255.250 Version=2}

Layer 3 packet From : 30:23:03:6b:d8:cc = 192.168.1.1, to : 01:00:5e:7f:ff:fa, 239.255.255.250
PACKET: 60 bytes, wire length 60 cap length 60 @ 2023-01-28 21:46:09.868655 -0500 EST
- Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..46..] SrcMAC=30:23:03:6b:d8:cc DstMAC=01:00:5e:7f:ff:fa EthernetType=IPv4 Length=0}
- Layer 2 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..8..] Version=4 IHL=5 TOS=192 Length=28 Id=44433 Flags= FragOffset=0 TTL=1 Protocol=IGMP Checksum=23019 SrcIP=192.168.1.1 DstIP=239.255.255.250 Options=[] Padding=[]}
- Layer 3 (00 bytes) = IGMP     {Contents=[] Payload=[] Type=IGMP Membership Query MaxResponseTime=10s Checksum=65184 GroupAddress=239.255.255.250 Version=2}
```

* Sniff network and get all ARP packets including devices that are NOT in the same IP Range, 
In this example I m executing the command from 192.168.1.100 and I found a device that has IP 10.0.0.1
Perfect for finding lost or misconfigured devices, or devices that they don't get IP Address from DHCP

```shell
./arpscansniff.exe -type sniff
2023/01/28 16:26:38 Found interface: \Device\NPF_{DF41CF6B-EC4B-46E8-99A7-743F21A641D8}
2023/01/28 16:26:38 Interface IP Address : 192.168.1.100

2023/01/28 16:26:38 Start monitoring interface: \Device\NPF_{DF41CF6B-EC4B-46E8-99A7-743F21A641D8}

ARP Packet From : 00:0f:ff:16:59:be = 10.0.0.1, to : 00:00:00:00:00:00, 8.8.4.4
PACKET: 60 bytes, wire length 60 cap length 60 @ 2023-01-28 16:26:38.416415 -0500 EST
- Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..46..] SrcMAC=00:0f:ff:16:59:be DstMAC=ff:ff:ff:ff:ff:ff EthernetType=ARP Length=0}
- Layer 2 (28 bytes) = ARP      {Contents=[..28..] Payload=[..18..] AddrType=Ethernet Protocol=IPv4 HwAddressSize=6 ProtAddressSize=4 Operation=1 SourceHwAddress=[..6..] SourceProtAddress=[10, 0, 0, 1] DstHwAddress=[..6..] DstProtAddress=[8, 8, 4, 4]}
- Layer 3 (18 bytes) = Payload  18 byte(s)
```





</br>