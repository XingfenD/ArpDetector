package main

import (
	"fmt"
	"net"
	"os"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: detector <file>")
		return
	}

	// 设置日志输出到抛弃
	logFile, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("无法打开日志文件:", err)
		return
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	handle, _ := pcap.OpenOffline(os.Args[1])

	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	ipStats := make(map[string](struct {
		synCount    int
		synAckCount int
	}))

	arpRequests := make(map[string](map[string]int))
	arpMAC := make(map[string]int)

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
			arp, _ := arpLayer.(*layers.ARP)
			srcIP := ip2str(arp.SourceProtAddress)
			srcMAC := mac2str(arp.SourceHwAddress)
			dstIP := ip2str(arp.DstProtAddress)
			dstMAC := mac2str(arp.DstHwAddress)

			if arp.Operation == layers.ARPRequest {
				if _, ok := arpRequests[srcIP]; !ok { /* if the ip is not recorded */
					arpRequests[srcIP] = make(map[string]int)
				}
				arpRequests[srcIP][dstMAC]++
				if dstMAC == "80:0b:98:3b:b9:ec"{
					log.Printf("ARP Request: %s (%s) -> %s (%s)\n", srcIP, srcMAC, dstIP, dstMAC)
				}
			} else if arp.Operation == layers.ARPReply {
				// log.Printf("ARP Reply: %s (%s) -> %s (%s)\n", srcIP, srcMAC, dstIP, dstMAC)
				if _, ok := arpRequests[dstIP]; ok {
					if arpRequests[dstIP][srcMAC] > 0 {
						arpRequests[dstIP][srcMAC]-- /* reduce the record */
					} else {
						arpMAC[srcMAC]++
						// log.Printf("ARP Spoofing suspected from MAC: %s\n", srcMAC)
					}
				} else {
					arpMAC[srcMAC]++
					// log.Printf("ARP Spoofing suspected from MAC: %s\n", srcMAC)
				}
				if srcMAC == "80:0b:98:3b:b9:ec" {
					log.Printf("ARP Reply: %s (%s) -> %s (%s)\n", srcIP, srcMAC, dstIP, dstMAC)
					log.Printf("Unauthorized Reply From %s Count %d\n", srcMAC, arpMAC[srcMAC])
					log.Printf("Request to %s Count %d", srcMAC, arpRequests[dstIP][srcMAC])
				}
			}
		}

	}

	fmt.Println("Unauthorized SYN scanners:")
	for ip, stats := range ipStats {
		if stats.synCount > 5 && stats.synCount > 3*stats.synAckCount {
			fmt.Println(ip)
		}
	}

	fmt.Println("Unauthorized ARP spoofers:")
	for mac, count := range arpMAC {
		log.Printf("ARP Spoofing suspected from MAC: %s, count:%d\n", mac, count)
		if count > 5 {
			fmt.Println(mac)
		}
	}
}

func ip2str(ip net.IP) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func mac2str(mac net.HardwareAddr) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
