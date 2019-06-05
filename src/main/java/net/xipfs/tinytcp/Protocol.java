package net.xipfs.tinytcp;

import org.pcap4j.packet.EthernetPacket;

/**
 * 
 * @author xiehui
 *
 */
public interface Protocol {
	void analyze(EthernetPacket packet) throws Exception;
}
