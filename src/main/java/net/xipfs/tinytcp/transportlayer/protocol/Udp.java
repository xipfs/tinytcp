package net.xipfs.tinytcp.transportlayer.protocol;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;

import net.xipfs.tinytcp.Protocol;
import net.xipfs.tinytcp.Tinytcp;

/**
 * Udp 协议
 * 
 * @author xiehui
 *
 */
public class Udp implements Protocol{

	@Override
	public void analyze(Packet packet) throws Exception {
		UdpPacket upacket = packet.get(UdpPacket.class);
		if(Tinytcp.cfg.get("udp.show").equals("1")) {
			System.out.println(upacket);
		}
	}

}
