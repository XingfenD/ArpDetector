package main

import (
	"fmt"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: detector <file>")
		return
	}

	handle, _ := pcap.OpenOffline(os.Args[1])

	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	ipStats := make(map[string](struct {
		synCount    int
		synAckCount int
	}))

	for packet := range packetSource.Packets() {
		/* SYN detect */
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		arpLayer := packet.Layer(layers.LayerTypeARP)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if tcpLayer != nil && ipLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			ip, _ := ipLayer.(*layers.IPv4)
			srcIP := net.IP(ip.SrcIP).String()
			dstIP := net.IP(ip.DstIP).String()

			srcStats := ipStats[srcIP]
			dstStats := ipStats[dstIP]
			if tcp.ACK && tcp.SYN {
				dstStats.synAckCount++
			} else if tcp.SYN {
				srcStats.synCount++
			}
			ipStats[srcIP] = srcStats
			ipStats[dstIP] = dstStats
		}

		/* ARP detect */
		if arpLayer != nil {
			// arp, _ := arpLayer.(*layers.ARP)

		}

	}

	fmt.Println("Unauthorized SYN scanners:")
	for ip, stats := range ipStats {
		if stats.synCount > 5 && stats.synCount > 3*stats.synAckCount {
			fmt.Println(ip)
		}
	}
	fmt.Println("Unauthorized ARP spoofers:")
}
