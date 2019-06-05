package net.xipfs.tinytcp.networklayer.protocol;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.IpV6Packet.IpV6Header;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IpNumber;

import net.xipfs.tinytcp.Protocol;
import net.xipfs.tinytcp.Tinytcp;

/**
 * IP - Internet Protocol
 * http://www.rfc-editor.org/rfc/rfc791.txt
 * 
 *                  Internet Datagram Header
 * 
 *   0                   1                   2                   3   
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Version|  IHL  |Type of Service|          Total Length         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Identification        |Flags|      Fragment Offset    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Time to Live |    Protocol   |         Header Checksum       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Source Address                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Destination Address                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Options                    |    Padding    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *                 
 *                     IPv6 Header Format
 *                  
 *  0                               16                              32
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Version| Traffic Class |           Flow Label                  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Payload Length        |  Next Header  |   Hop Limit   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +                         Source Address                        +
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +                      Destination Address                      +
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                
 *                  
 * @author xiehui
 *
 */
public class IP implements Protocol{
	
	/**
	 * 分析 ip 包，目前支持 ipv4 与 ipv6
	 */
	public void analyze(Packet packet) {
		if(packet.contains(IpV4Packet.class)) {
			IpV4Packet ipacket = packet.get(IpV4Packet.class);
			IpV4Header iheader = ipacket.getHeader();
			iheader.getVersion();
			iheader.getIhl();
			iheader.getTos();
			iheader.getTotalLength();
			iheader.getIdentification();
			// Flags: (Reserved, Don't Fragment, More Fragment) 
			iheader.getReservedFlag();
			iheader.getDontFragmentFlag();
			iheader.getMoreFragmentFlag();
			iheader.getFragmentOffset();
			iheader.getTtl();
			iheader.getProtocol();
			iheader.getHeaderChecksum();
			iheader.getSrcAddr();
			iheader.getDstAddr();
			iheader.getOptions();
			iheader.getPadding();
			if(Tinytcp.cfg.get("ip.show").equals("1")) {
				System.out.println(iheader);
			}
			// ICMPV4 协议
			if(iheader.getProtocol().compareTo(IpNumber.ICMPV4) ==0 ) {
				System.out.println(packet);
			}
		}else if(packet.contains(IpV6Packet.class)) {
			IpV6Packet ipacket = packet.get(IpV6Packet.class);
			IpV6Header iheader = ipacket.getHeader();
			iheader.getVersion();
			iheader.getTrafficClass();
			iheader.getFlowLabel();
			iheader.getPayloadLength();
			iheader.getNextHeader();
			iheader.getHopLimit();
			iheader.getSrcAddr();
			iheader.getDstAddr();
			
			// ICMPV6 协议
			if(iheader.getProtocol().compareTo(IpNumber.ICMPV6) ==0 ) {
				
			}
		}
	}
}
