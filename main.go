package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var scanType = flag.String("type", "scan", "Choose between scan OR sniff, scan network every 10 sec or sniff all packets")
var packetFilter = flag.String("filter", "", "Packet filter for capture, e.g. arp / tcp and port 80 / udp and port 53")
var macFilter = flag.String("mac", "", "Mac address filter, e.g. (3 digits) 30:23:03 / (full mac) 80:ce:62:e8:9b:f5")
var packetLen = flag.Int("len", 1024, "Maximun size to read for each packet, ")
var promiscuousMode = flag.Bool("promisc", false, "Enable promiscuous mode to monitor network,  (default false)")
var timeoutConnection = flag.Int("timeout", 30, "Connection Timeout in seconds, ")
var mac = map[string]string{}

func main() {
	flag.Parse()

	var timeout time.Duration = time.Duration(*timeoutConnection) * time.Second

	// Get a list of all interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	// Get a list of all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	var deviceWinId = ""
	var deviceIPnet *net.IPNet
	//var test *net.IPNet
	var iface net.Interface

	// Scan interfaces to find the correct one
	for _, iface = range ifaces {
		// get the first right network interface for sniffing.
		deviceWinId, _, err = getRightInterface(&iface, &devices)
		if err != nil {
			log.Printf("Skipping interface %v: %v", iface.Name, err)
		} else {
			log.Printf("Found interface: %v", deviceWinId)
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok {
					if ip4 := ipnet.IP.To4(); ip4 != nil {
						log.Printf("Interface IP Address : %v", ip4)
						//deviceIPnet = *ipnet

						deviceIPnet = &net.IPNet{
							IP:   ip4, //net.IPv4(0, 0, 0, 0), //ip4,
							Mask: ipnet.Mask[len(ipnet.Mask)-4:],
						}
						break
					}
				}
			}

			break
		}

	}

	// Build mac address list
	json.Unmarshal([]byte(macJson), &mac)

	// Build all IP Addresses from your network adapter
	var allIPs = buildIPs(deviceIPnet)

	if *scanType == "scan" {

		handle, err := pcap.OpenLive(deviceWinId, 65536, true, pcap.BlockForever)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()

		// goroutine to read incoming packet data.
		stop := make(chan struct{})
		go readARP_Packets(handle, &iface, stop)
		defer close(stop)
		for {
			// Send packets to our network.
			if err := sendARP_Packets(handle, &iface, allIPs, deviceIPnet); err != nil { //&deviceIPnet
				log.Printf("error writing packets on %v: %v", iface.Name, err)
			}

			//Sleep 10 until the next loop
			time.Sleep(10 * time.Second)
		}
	}

	if *scanType == "sniff" {
		sniffMyNetwork(deviceWinId, timeout)
	}
}

func buildIPs(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	ipvalue := num & mask
	broadcast := ipvalue | ^mask
	for ipvalue++; ipvalue < broadcast; ipvalue++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], ipvalue)
		out = append(out, net.IP(buf[:]))
	}

	return
}

func sniffMyNetwork(deviceWinId string, timeout time.Duration) {
	fmt.Println("")
	log.Printf("Start monitoring interface: %v", deviceWinId)
	fmt.Println("")

	// Open Device
	handle, err := pcap.OpenLive(deviceWinId, int32(*packetLen), *promiscuousMode, timeout)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	// Apply BPF Filter if exists
	if *packetFilter != "" {
		log.Println("Active filter : ", *packetFilter)
		err := handle.SetBPFFilter(*packetFilter)
		if err != nil {
			log.Fatalf("error using BPF Filter %s - %v", *packetFilter, err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// 1. Physical
		// 2. Data link
		// 3. Network
		// 4. Transport

		if len(packet.Layers()) == 2 {
			osiLayer := packet.Layer(layers.LayerTypeARP)
			netData := osiLayer.(*layers.ARP)
			fmt.Printf("ARP Packet From : %v = %v, to : %v, %v\r\n",
				net.HardwareAddr(netData.SourceHwAddress),
				net.IP(netData.SourceProtAddress),
				net.HardwareAddr(netData.DstHwAddress),
				net.IP(netData.DstProtAddress))
			fmt.Println(packet)
		}
	}
}

func getRightInterface(iface *net.Interface, devices *[]pcap.Interface) (string, *net.Interface, error) {
	// Look for IPv4 addresses, try to find if the interface has one.
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return "", nil, err
	} else {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}

	// Check if interface has a good address for packet monitoring.
	if addr == nil {
		return "", nil, errors.New("no good IP network found")
	} else if addr.IP[0] == 127 {
		return "", nil, errors.New("skipping localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return "", nil, errors.New("network is too large")
	}

	// Find a match between device and interface using the IP Address, get the device ID for windows use
	var deviceWinId string
	for _, d := range *devices {
		if strings.Contains(fmt.Sprint(d.Addresses), fmt.Sprint(addr.IP)) {
			deviceWinId = d.Name
		}
	}

	if deviceWinId == "" {
		err := fmt.Sprintf("cannot find the windows device ID for the interface %v", iface.Name)
		return "", nil, errors.New(err)
	}

	return deviceWinId, iface, nil
}

func readARP_Packets(handle *pcap.Handle, iface *net.Interface, stop chan struct{}) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet) //LayerTypeEthernet
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
				continue
			}

			macString := net.HardwareAddr(arp.SourceHwAddress).String()
			manuf := getBrand(macString)
			printValue := true
			if *macFilter != "" {
				printValue = strings.HasPrefix(strings.ToUpper(macString), strings.ToUpper(*macFilter))
			}
			//Log ARP packets
			if printValue {
				fmt.Printf("IP %15s -> %v -> %v", net.IP(arp.SourceProtAddress), macString, manuf)
				fmt.Println()
			}
		}
	}
}

func sendARP_Packets(handle *pcap.Handle, iface *net.Interface, addresses []net.IP, addr *net.IPNet) error {

	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4, //layers.EthernetTypeARP, // layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP), //[]byte{0, 0, 0, 0}, //, //[]byte(addr.IP), //
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	fmt.Println("*")

	// Send ARP packets.
	for _, ip := range addresses {
		arp.DstProtAddress = []byte(ip)
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}
