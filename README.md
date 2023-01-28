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

</br>