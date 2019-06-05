package net.xipfs.tinytcp;

import org.pcap4j.packet.Packet;

/**
 * 
 * @author xiehui
 *
 */
public interface Protocol {
	void analyze(Packet packet) throws Exception;
}
