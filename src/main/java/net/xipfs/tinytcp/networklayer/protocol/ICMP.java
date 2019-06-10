package net.xipfs.tinytcp.networklayer.protocol;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.pcap4j.packet.AbstractPacket.AbstractBuilder;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4CommonPacket.IcmpV4CommonHeader;
import org.pcap4j.packet.IcmpV4DestinationUnreachablePacket;
import org.pcap4j.packet.IcmpV4DestinationUnreachablePacket.IcmpV4DestinationUnreachableHeader;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IcmpV4EchoPacket.IcmpV4EchoHeader;
import org.pcap4j.packet.IcmpV4EchoReplyPacket;
import org.pcap4j.packet.IcmpV4EchoReplyPacket.IcmpV4EchoReplyHeader;
import org.pcap4j.packet.IcmpV4InformationReplyPacket;
import org.pcap4j.packet.IcmpV4InformationReplyPacket.IcmpV4InformationReplyHeader;
import org.pcap4j.packet.IcmpV4InformationRequestPacket;
import org.pcap4j.packet.IcmpV4InformationRequestPacket.IcmpV4InformationRequestHeader;
import org.pcap4j.packet.IcmpV4ParameterProblemPacket;
import org.pcap4j.packet.IcmpV4ParameterProblemPacket.IcmpV4ParameterProblemHeader;
import org.pcap4j.packet.IcmpV4RedirectPacket;
import org.pcap4j.packet.IcmpV4RedirectPacket.IcmpV4RedirectHeader;
import org.pcap4j.packet.IcmpV4SourceQuenchPacket;
import org.pcap4j.packet.IcmpV4SourceQuenchPacket.IcmpV4SourceQuenchHeader;
import org.pcap4j.packet.IcmpV4TimeExceededPacket;
import org.pcap4j.packet.IcmpV4TimeExceededPacket.IcmpV4TimeExceededHeader;
import org.pcap4j.packet.IcmpV4TimestampPacket;
import org.pcap4j.packet.IcmpV4TimestampPacket.IcmpV4TimestampHeader;
import org.pcap4j.packet.IcmpV4TimestampReplyPacket;
import org.pcap4j.packet.IcmpV4TimestampReplyPacket.IcmpV4TimestampReplyHeader;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.IpV4Helper;
import org.pcap4j.util.MacAddress;

import net.xipfs.tinytcp.Protocol;
import net.xipfs.tinytcp.Tinytcp;
import net.xipfs.tinytcp.datalinklayer.DatalinkLayer;

/**
 * https://tools.ietf.org/html/rfc792
 * 
 * +------+ +-----+ +-----+     +-----+
 * |Telnet| | FTP | | TFTP| ... | ... |
 * +------+ +-----+ +-----+     +-----+
 *       |   |         |           |
 *      +-----+     +-----+     +-----+
 *      | TCP |     | UDP | ... | ... |
 *      +-----+     +-----+     +-----+
 *         |           |           |
 *     +--------------------------+----+
 *     |    Internet Protocol & ICMP   |
 *     +--------------------------+----+
 *                     |
 *     +---------------------------+
 *     |   Local Network Protocol  |
 *     +---------------------------+
 *
 *        Protocol Relationships
 *        
 *        
 * @author xiehui
 *
 */
public class ICMP implements Protocol{

	@Override
	public void analyze(Packet packet){
		if(packet.contains(IcmpV4CommonPacket.class)) {
			IcmpV4CommonPacket ipacket = packet.get(IcmpV4CommonPacket.class);
			IcmpV4CommonHeader iheader = ipacket.getHeader();
			iheader.getType();
			iheader.getCode();
			iheader.getCode();
		}
		if(packet.contains(IcmpV4EchoPacket.class)) {
			IcmpV4EchoPacket ipacket = packet.get(IcmpV4EchoPacket.class);
			IcmpV4EchoHeader iheader = ipacket.getHeader();
			iheader.getIdentifier();
			iheader.getSequenceNumber();
		}
		if(packet.contains(IcmpV4EchoReplyPacket.class)) {
			IcmpV4EchoReplyPacket ipacket = packet.get(IcmpV4EchoReplyPacket.class);
			IcmpV4EchoReplyHeader iheader = ipacket.getHeader();
			iheader.getIdentifier();
			iheader.getSequenceNumber();
		}
		if(packet.contains(IcmpV4DestinationUnreachablePacket.class)) {
			IcmpV4DestinationUnreachablePacket ipacket = packet.get(IcmpV4DestinationUnreachablePacket.class);
			IcmpV4DestinationUnreachableHeader iheader = ipacket.getHeader();
			iheader.getUnused();
		}
		if(packet.contains(IcmpV4InformationReplyPacket.class)) {
			IcmpV4InformationReplyPacket ipacket = packet.get(IcmpV4InformationReplyPacket.class);
			IcmpV4InformationReplyHeader iheader = ipacket.getHeader();
			iheader.getIdentifier();
			iheader.getSequenceNumber();
		}
		if(packet.contains(IcmpV4InformationRequestPacket.class)) {
			IcmpV4InformationRequestPacket ipacket = packet.get(IcmpV4InformationRequestPacket.class);
			IcmpV4InformationRequestHeader iheader = ipacket.getHeader();
			iheader.getIdentifier();
			iheader.getSequenceNumber();
		}
		if(packet.contains(IcmpV4ParameterProblemPacket.class)) {
			IcmpV4ParameterProblemPacket ipacket = packet.get(IcmpV4ParameterProblemPacket.class);
			IcmpV4ParameterProblemHeader iheader = ipacket.getHeader();
			iheader.getPointer();
			iheader.getUnused();
		}
		if(packet.contains(IcmpV4SourceQuenchPacket.class)) {
			IcmpV4SourceQuenchPacket ipacket = packet.get(IcmpV4SourceQuenchPacket.class);
			IcmpV4SourceQuenchHeader iheader = ipacket.getHeader();
			iheader.getUnused();
		}
		if(packet.contains(IcmpV4TimeExceededPacket.class)) {
			IcmpV4TimeExceededPacket ipacket = packet.get(IcmpV4TimeExceededPacket.class);
			IcmpV4TimeExceededHeader iheader = ipacket.getHeader();
			iheader.getUnused();
		}
		if(packet.contains(IcmpV4RedirectPacket.class)) {
			IcmpV4RedirectPacket ipacket = packet.get(IcmpV4RedirectPacket.class);
			IcmpV4RedirectHeader iheader = ipacket.getHeader();
			iheader.getGatewayInternetAddress();
		}
		if(packet.contains(IcmpV4TimestampPacket.class)) {
			IcmpV4TimestampPacket ipacket = packet.get(IcmpV4TimestampPacket.class);
			IcmpV4TimestampHeader iheader = ipacket.getHeader();
			iheader.getIdentifier();
			iheader.getOriginateTimestamp();
			iheader.getReceiveTimestamp();
			iheader.getSequenceNumber();
			iheader.getTransmitTimestamp();
		}
		if(packet.contains(IcmpV4TimestampReplyPacket.class)) {
			IcmpV4TimestampReplyPacket ipacket = packet.get(IcmpV4TimestampReplyPacket.class);
			IcmpV4TimestampReplyHeader iheader = ipacket.getHeader();
			iheader.getIdentifier();
			iheader.getOriginateTimestamp();
			iheader.getReceiveTimestamp();
			iheader.getSequenceNumber();
			iheader.getTransmitTimestamp();
		}
		if(Tinytcp.cfg.get("icmp.show").equals("1")) {
			System.out.println(packet);
		}
	}
	
	public static void sendIcmpPacket(String strSrcIpAddress, String strSrcMacAddress, String strDstIpAddress,String strDstMacAddress) {
	    byte[] echoData = new byte[4000 - 28];
	    for (int i = 0; i < echoData.length; i++) {
	    	echoData[i] = (byte) i;
	    }
		IcmpV4EchoPacket.Builder echoBuilder = new IcmpV4EchoPacket.Builder();
		echoBuilder.identifier((short) 1).payloadBuilder(new UnknownPacket.Builder().rawData(echoData));

		IcmpV4CommonPacket.Builder icmpV4CommonBuilder = new IcmpV4CommonPacket.Builder();
		icmpV4CommonBuilder.type(IcmpV4Type.ECHO).code(IcmpV4Code.NO_CODE).payloadBuilder(echoBuilder)
				.correctChecksumAtBuild(true);

		IpV4Packet.Builder ipV4Builder = new IpV4Packet.Builder();
	    try {
	          ipV4Builder
	              .version(IpVersion.IPV4)
	              .tos(IpV4Rfc791Tos.newInstance((byte) 0))
	              .ttl((byte) 100)
	              .protocol(IpNumber.ICMPV4)
	              .srcAddr((Inet4Address) InetAddress.getByName(strSrcIpAddress))
	              .dstAddr((Inet4Address) InetAddress.getByName(strDstIpAddress))
	              .payloadBuilder(icmpV4CommonBuilder)
	              .correctChecksumAtBuild(true)
	              .correctLengthAtBuild(true);
	    } catch (UnknownHostException e1) {
	    	throw new IllegalArgumentException(e1);
	    }
	    MacAddress srcMacAddr = MacAddress.getByName(strSrcMacAddress, ":");
		EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
		etherBuilder.dstAddr(MacAddress.getByName(strDstMacAddress, ":")).srcAddr(srcMacAddr).type(EtherType.IPV4)
				.paddingAtBuild(true);
	    echoBuilder.sequenceNumber((short)1);
        ipV4Builder.identification((short)1);

        for (final Packet ipV4Packet : IpV4Helper.fragment(ipV4Builder.build(), 1403)) {
	        etherBuilder.payloadBuilder(
	              new AbstractBuilder() {
	                @Override
	                public Packet build() {
	                  return ipV4Packet;
	                }
	              });
	
	         Packet packet = etherBuilder.build();
	         DatalinkLayer.addPacket(packet);
        }
	}

}
