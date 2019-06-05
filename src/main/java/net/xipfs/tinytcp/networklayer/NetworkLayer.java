package net.xipfs.tinytcp.networklayer;

import org.pcap4j.packet.Packet;

import net.xipfs.tinytcp.networklayer.protocol.IP;

/**
 * 网络层
 * 
 * @author root
 *
 */
public class NetworkLayer {
	public void receivePacket(Packet packet) {
		new IP().analyze(packet);
	}
}
