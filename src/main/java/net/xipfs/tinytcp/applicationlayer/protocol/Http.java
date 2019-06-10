package net.xipfs.tinytcp.applicationlayer.protocol;

import org.pcap4j.packet.Packet;

import net.xipfs.tinytcp.Protocol;
import net.xipfs.tinytcp.Tinytcp;

public class Http implements Protocol{
	@Override
	public void analyze(Packet packet) throws Exception {
		if(Tinytcp.cfg.get("http.show").equals("1")) {
			System.out.println(packet);
		}
	}

}
