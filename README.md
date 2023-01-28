# ARP Packet scanner and sniffer with GoLang (Windows compatible)

CLI command for scanning and monitoring ARP Packets, discover devices, troobleshoot defective devices and more.

## Overview
This is a Golang CLI command easy to use and troobleshoot local networks Link Layer (OSI Model Layer 2).</br>
It contains a manufacturer database to resolve each mac address to the Brand name that belogs.</br>

Inspired from many packet sniffers around github and https://pkg.go.dev/github.com/google/gopacket package.</br>

## Usage
```shell
Usage of arpscansniff.exe:
  -filter string
        Packet filter for capture, e.g. arp / tcp and port 80 / udp and port 53
  -len int
        Maximun size to read for each packet,  (default 1024)
  -mac string
        Mac address filter, e.g. (3 digits) 30:23:03 / (full mac) 80:ce:62:e8:9b:f5
  -promisc
        Enable promiscuous mode to monitor network,  (default false)
  -timeout int
        Connection Timeout in seconds,  (default 30)
  -type string
        Choose between scan OR sniff, scan network every 10 sec or sniff all packets (default "scan")
```

## Examples and Use cases

Scan network and get all MAC from active devices.
Command will find your active network connection and automatically will scan all IP addresses.
ARP Scan does't guarandee responce from all devices especially the devices that they are in stand by mode thats why it will perform the scan every 10 seconds.

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



Devices that they don't get IP Address from DHCP Server
</br>