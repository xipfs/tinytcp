package net.xipfs.tinytcp.networklayer.protocol;

import org.pcap4j.packet.EthernetPacket;

import net.xipfs.tinytcp.Protocol;

/**
 * https://tools.ietf.org/html/rfc792
 * 
 * +------+ +-----+ +-----+     +-----+
 * |Telnet| | FTP | | TFTP| ... | ... |
 * +------+ +-----+ +-----+     +-----+
 *       |   |         |           |
 *      +-----+     +-----+     +-----+
 *      | TCP |     | UDP | ... | ... |
 *      +-----+     +-----+     +-----+
 *         |           |           |
 *     +--------------------------+----+
 *     |    Internet Protocol & ICMP   |
 *     +--------------------------+----+
 *                     |
 *     +---------------------------+
 *     |   Local Network Protocol  |
 *     +---------------------------+
 *
 *        Protocol Relationships
 *        
 *        
 * @author xiehui
 *
 */
public class ICMP implements Protocol{

	@Override
	public void analyze(EthernetPacket packet) throws Exception {
		
	}

}
