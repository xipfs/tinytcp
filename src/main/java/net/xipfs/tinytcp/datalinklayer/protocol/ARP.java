package net.xipfs.tinytcp.datalinklayer.protocol;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.ArpPacket.ArpHeader;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

import net.xipfs.tinytcp.Protocol;
import net.xipfs.tinytcp.Tinytcp;
import net.xipfs.tinytcp.datalinklayer.DatalinkLayer;

/**
 * ARP - Address Resolution Protocol
 * http://www.rfc-editor.org/rfc/rfc826.txt
 * 
 * |         --------         |
 * |         |  IP  |         |
 * |  -----  -*----*-  -----  |
 * |  |ARP|   |    |   |ARP|  |
 * |  -----   |    |   -----  |
 * |      \   |    |   /      |
 * |      ------  ------      |
 * |      |ENET|  |ENET|      |
 * |      ---@--  ---@--      |
 * ----------|-------|---------
 *           |       |
 *           |    ---o---------------------------
 *           |   Ethernet Cable 2
 * ----------o----------
 *     Ethernet Cable 1
 * 
 *          ARP 数据包格式
 *  0                            15
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Hardware Type         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Protocol Type         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  HW Addr Len  |Proto Addr Len |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Operation             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Src Hardware Address       |
 * +                               +
 * |                               |
 * +                               +
 * |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Src Protocol Address       |
 * +                               |
 * |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Dst Hardware Address       |
 * +                               +
 * |                               |
 * +                               +
 * |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Dst Protocol Address       |
 * +                               |
 * |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 清除 arp 缓存 
 * sudo arp -n|awk '/^[1-9]/{system("sudo arp -d "$1)}'
 * 
 * @author xiehui
 */

public class ARP implements Protocol{
	
	/**
	 * 分析 Arp 数据包
	 */
	@Override
	public void analyze(Packet packet) throws Exception {
		byte[] bytes = packet.getRawData();
		//Utils.printHexString(bytes);
		
		// 跳过以太网帧头14字节
		ArpPacket apacket = ArpPacket.newPacket(bytes,DatalinkLayer.EthernetHeaderLength,bytes.length-DatalinkLayer.EthernetHeaderLength);
		ArpHeader aheader = apacket.getHeader();
		aheader.getHardwareType();
		aheader.getProtocolType();
		aheader.getHardwareAddrLength();
		aheader.getProtocolAddrLength();
		aheader.getOperation();
		aheader.getSrcHardwareAddr();
		aheader.getSrcProtocolAddr();
		aheader.getDstHardwareAddr();
		aheader.getDstProtocolAddr();
		if(Tinytcp.cfg.get("arp.show").equals("1")) {
			System.out.println(packet);
		}
	}
	
	/**
	 * 构建 Arp 数据包，然后发送出去
	 */
	public static void sendArpPacket(String srcMac, String srcIp,String dstIp) {
		System.out.println(srcMac);
		System.out.println(srcIp);
		System.out.println(dstIp);
          MacAddress SRC_MAC_ADDR = MacAddress.getByName(srcMac);
	      ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
	      try {
	        arpBuilder
	            .hardwareType(ArpHardwareType.ETHERNET)
	            .protocolType(EtherType.IPV4)
	            .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
	            .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
	            .operation(ArpOperation.REQUEST)
	            .srcHardwareAddr(SRC_MAC_ADDR)
	            .srcProtocolAddr(InetAddress.getByName(srcIp))
	            .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
	            .dstProtocolAddr(InetAddress.getByName(dstIp));
	      } catch (UnknownHostException e) {
	        throw new IllegalArgumentException(e);
	      }

	      EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
	      etherBuilder
	          .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
	          .srcAddr(SRC_MAC_ADDR)
	          .type(EtherType.ARP)
	          .payloadBuilder(arpBuilder)
	          .paddingAtBuild(true);
	      Packet packet = etherBuilder.build();
	      DatalinkLayer.addPacket(packet);
	}
	
}
