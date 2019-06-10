package net.xipfs.tinytcp.transportlayer;

import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import net.xipfs.tinytcp.applicationlayer.ApplicationLayer;
import net.xipfs.tinytcp.transportlayer.protocol.Tcp;
import net.xipfs.tinytcp.transportlayer.protocol.Udp;

/**
 * 传输层
 * 
 * @author xiehui
 *
 */
public class TransportLayer {
	private ApplicationLayer appLayer = new ApplicationLayer();
	public void receivePacket(Packet packet) throws Exception {
		if(packet.contains(TcpPacket.class)) {
			new Tcp().analyze(packet);
		}
		if(packet.contains(UdpPacket.class)) {
			new Udp().analyze(packet);
		}
		
		if(packet.contains(DnsPacket.class)) {
			// 交给应用层分析消息
			appLayer.receivePacket(packet);
		}
	}

}
