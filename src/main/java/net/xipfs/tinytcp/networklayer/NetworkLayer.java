package net.xipfs.tinytcp.networklayer;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import net.xipfs.tinytcp.networklayer.protocol.IP;
import net.xipfs.tinytcp.transportlayer.TransportLayer;

/**
 * 网络层
 * 
 * @author root
 *
 */
public class NetworkLayer {
	private TransportLayer transportLayer = new TransportLayer();
	public void receivePacket(Packet packet) throws Exception {
		new IP().analyze(packet); // 分析 ip 头
		if(packet.contains(TcpPacket.class) || packet.contains(UdpPacket.class)) {
			// 交给传输层分析消息
			transportLayer.receivePacket(packet);
		}
	}
}
