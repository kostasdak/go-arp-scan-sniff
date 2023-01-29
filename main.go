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
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var netInterface = flag.Int("iface", -1, "Override the automatic network card, choose a specific interface from the list")
var scanType = flag.String("type", "scan", "Choose between scan/sniff, scan network every 10 sec or sniff all packets")
var packetFilter = flag.String("filter", "arp", "Packet filter for capture, e.g. arp / all")
var packetLimit = flag.Int("limit", 0, "Limit the number of captured packets, use it in busy networks with -mac filter")
var macFilter = flag.String("mac", "", "Mac address filter, e.g. (3 digits) 30:23:03 / (full addr) 80:ce:62:e8:9b:f5")
var promiscuousMode = flag.Bool("promisc", true, "Enable/Disable promiscuous mode to monitor network")
var mac = map[string]string{}

func main() {
	flag.Parse()

	if strings.ToLower(*packetFilter) != "all" && strings.ToLower(*packetFilter) != "arp" {
		log.Fatal("filter option must be arp or all")
		os.Exit(1)
	}
	if strings.ToLower(*scanType) != "scan" && strings.ToLower(*scanType) != "sniff" {
		log.Fatal("scan type must be scan or sniff")
		os.Exit(1)
	}

	var timeout time.Duration = time.Duration(30) * time.Microsecond

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
	var deviceWinInterface *net.Interface
	var deviceIPnet *net.IPNet
	var iface net.Interface

	// Loop through interfaces and display to user
	for i, tmp := range ifaces {
		fmt.Printf("#%v Interface: %v\r\n", i, tmp.Name)
	}

	// User must choose the right interface
	if *netInterface == -1 {
		fmt.Println("Choose a network interface by using the switch -iface following by the number of the interface")
		os.Exit(0)
	}

	// check if netInterface is valid
	if *netInterface < 0 || *netInterface > len(ifaces) {
		log.Fatalln("Wrong interface number !!!")
		os.Exit(1)
	}

	// get the network interface for sniffing.
	iface = ifaces[*netInterface]
	deviceWinId, deviceWinInterface, err = getInterfaceParams(&iface, &devices)
	if err != nil {
		log.Fatalf("Error using interface: %v -> %v\r\n", iface.Name, err)
		os.Exit(1)
	} else {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					deviceIPnet = &net.IPNet{
						IP:   ip4, //net.IPv4(0, 0, 0, 0), //ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}

	// Displey info before start
	fmt.Println("In case you want to choose a different network interface use the switch -iface following by the number of the interface")
	fmt.Println("")
	fmt.Printf("Found interface: %v -> %v\r\n", deviceWinInterface.Name, deviceWinId)
	fmt.Printf("Interface IP Address: %v\r\n", deviceIPnet.IP)

	// Build mac address list
	json.Unmarshal([]byte(macJson), &mac)

	// Build all IP Addresses from your network adapter
	var allIPs = buildIPs(deviceIPnet)

	if strings.ToLower(*scanType) == "scan" {

		handle, err := pcap.OpenLive(deviceWinId, 65536, true, pcap.BlockForever)
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
		defer handle.Close()

		// goroutine to read incoming packet data.
		stop := make(chan struct{})
		go readARP_Packets(handle, &iface, stop)
		defer close(stop)
		for {
			// Send packets to our network.
			if err := sendARP_Packets(handle, &iface, allIPs, deviceIPnet); err != nil { //&deviceIPnet
				log.Fatalf("error writing packets on %v: %v", iface.Name, err)
				os.Exit(1)
			}

			//Sleep 10 until the next loop
			time.Sleep(10 * time.Second)
		}
	}

	if strings.ToLower(*scanType) == "sniff" {
		sniffMyNetwork(deviceWinId, deviceWinInterface, timeout)
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

func sniffMyNetwork(deviceWinId string, iface *net.Interface, timeout time.Duration) {
	fmt.Println("")
	fmt.Printf("Start monitoring interface: %v\r\n", deviceWinId)

	myMac := net.HardwareAddr(iface.HardwareAddr).String()
	packetCount := 0

	// Open Device, packet size 1024
	handle, err := pcap.OpenLive(deviceWinId, 65535, *promiscuousMode, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	defer handle.Close()

	// Apply BPF Filter if exists
	if *packetFilter != "" {
		if strings.ToLower(*packetFilter) == "arp" {
			fmt.Println("Filter applied: ", *packetFilter)
			err := handle.SetBPFFilter(*packetFilter)
			if err != nil {
				log.Fatalf("error using BPF filter %s - %v", *packetFilter, err)
				os.Exit(1)
			}
		}
		if strings.ToLower(*packetFilter) == "all" {
			*packetFilter = ""
		}
	}

	fmt.Println("")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// 1. Physical
		// 2. Data link
		// 3. Network
		// 4. Transport
		layerVal := len(packet.Layers())

		if strings.ToLower(*packetFilter) == "arp" {
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer != nil {
				arpData := arpLayer.(*layers.ARP)
				fmt.Printf("ARP Packet From : %v = %v, to : %v, %v\r\n",
					net.HardwareAddr(arpData.SourceHwAddress),
					net.IP(arpData.SourceProtAddress),
					net.HardwareAddr(arpData.DstHwAddress),
					net.IP(arpData.DstProtAddress))
				fmt.Println(packet)
				packetCount++
				if packetCount == *packetLimit {
					os.Exit(0)
				}
			}
		} else {
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			ethData := ethLayer.(*layers.Ethernet)
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			ip6Layer := packet.Layer(layers.LayerTypeIPv6)

			// Exclude packets from my Mac
			if myMac != net.HardwareAddr(ethData.DstMAC).String() && myMac != net.HardwareAddr(ethData.SrcMAC).String() {
				macString := net.HardwareAddr(ethData.SrcMAC).String()
				printPacket := true
				if *macFilter != "" {
					printPacket = strings.HasPrefix(strings.ToUpper(macString), strings.ToUpper(*macFilter))
				}

				if printPacket {
					if ipLayer != nil {
						ipData := ipLayer.(*layers.IPv4)

						fmt.Printf("Layer %v packet From : %v = %v, to : %v, %v\r\n",
							layerVal,
							ethData.SrcMAC,
							ipData.SrcIP,
							ethData.DstMAC,
							ipData.DstIP,
						)

					} else if ip6Layer != nil {

						ip6Data := ip6Layer.(*layers.IPv6)

						fmt.Printf("Layer %v packet From : %v = %v, to : %v, %v\r\n",
							layerVal,
							ethData.SrcMAC,
							ip6Data.SrcIP,
							ethData.DstMAC,
							ip6Data.DstIP,
						)

					} else {

						fmt.Printf("Layer %v packet From : %v to : %v\r\n",
							layerVal,
							ethData.SrcMAC,
							ethData.DstMAC,
						)

					}

					fmt.Println(packet)
					packetCount++
					if packetCount == *packetLimit {
						os.Exit(0)
					}
				}
			}
		}
	}
}

func getInterfaceParams(iface *net.Interface, devices *[]pcap.Interface) (string, *net.Interface, error) {
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
			printPacket := true
			if *macFilter != "" {
				printPacket = strings.HasPrefix(strings.ToUpper(macString), strings.ToUpper(*macFilter))
			}
			//Log ARP packets
			if printPacket {
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
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
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
