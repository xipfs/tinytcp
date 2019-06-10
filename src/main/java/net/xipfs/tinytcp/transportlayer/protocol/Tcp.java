package net.xipfs.tinytcp.transportlayer.protocol;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpHeader;

import net.xipfs.tinytcp.Protocol;
import net.xipfs.tinytcp.Tinytcp;

/**
 * Tcp 协议
 * @author xiehui
 *
 */
public class Tcp implements Protocol{

	@Override
	public void analyze(Packet packet) throws Exception {
		TcpPacket tpacket = packet.get(TcpPacket.class);
		if(Tinytcp.cfg.get("tcp.show").equals("1")) {
			System.out.println(tpacket);
		}
		TcpHeader theader = tpacket.getHeader();
		if(theader.getDstPort().valueAsInt() == 8888) {
			System.out.println("80 端口监听到数据");
			System.out.println(tpacket);
			System.out.println(new String(theader.getRawData()));
		}
		
	}

}
