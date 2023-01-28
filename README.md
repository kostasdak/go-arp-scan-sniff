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

* Sniff network and get all ARP packets including devices that are NOT in the same IP Range, perfect for finding lost or misconfigured devices
```shell
./arpscansniff.exe -type sniff -filter arp
2023/01/28 13:46:19 Found interface: \Device\NPF_{DF41CF6B-EC4B-46E8-99A7-743F21A641D8}
2023/01/28 13:46:19 Interface IP Address : 192.168.1.100

2023/01/28 13:46:19 Start monitoring interface: \Device\NPF_{DF41CF6B-EC4B-46E8-99A7-743F21A641D8}
2023/01/28 13:46:19 Active filter :  arp

ARP Packet From : 34:17:eb:c2:03:03 = 192.168.1.100, to : 30:23:03:6b:d8:cc, 192.168.1.1
PACKET: 42 bytes, wire length 42 cap length 42 @ 2023-01-28 13:46:29.266638 -0500 EST
- Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..28..] SrcMAC=34:17:eb:c2:03:03 DstMAC=30:23:03:6b:d8:cc EthernetType=ARP Length=0}
- Layer 2 (28 bytes) = ARP      {Contents=[..28..] Payload=[] AddrType=Ethernet Protocol=IPv4 HwAddressSize=6 ProtAddressSize=4 Operation=2 SourceHwAddress=[..6..] SourceProtAddress=[192, 168, 1, 100] DstHwAddress=[..6..] DstProtAddress=[192, 168, 1, 1]}
```





Devices that they don't get IP Address from DHCP Server

</br>