package net.xipfs.tinytcp.applicationlayer.protocol;

import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsPacket.DnsHeader;
import org.pcap4j.packet.Packet;

import net.xipfs.tinytcp.Protocol;
import net.xipfs.tinytcp.Tinytcp;

public class Dns implements Protocol{

	@Override
	public void analyze(Packet packet) throws Exception {
		DnsPacket dpacket = packet.get(DnsPacket.class);
        DnsHeader dHeader = packet.get(DnsPacket.class).getHeader();
        if (dHeader.isResponse()) {
        	dHeader.getAnswers().get(0).getName();
        } else {
        	dHeader.getQuestions();
            // DNS 记录类型
        	dHeader.getQuestions().get(0).getQType();
        }
		if(Tinytcp.cfg.get("dns.show").equals("1")) {
			System.out.println(dpacket);
		}
	}

}
