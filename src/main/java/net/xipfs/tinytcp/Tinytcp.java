package net.xipfs.tinytcp;

import java.util.Properties;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.util.NifSelector;

import net.xipfs.tinytcp.datalinklayer.DatalinkLayer;
import net.xipfs.tinytcp.datalinklayer.protocol.ARP;
import net.xipfs.tinytcp.networklayer.protocol.ICMP;

/**
 * 网络数据分析
 * 
 *  * ----------------------------
 * |    network applications  |
 * |                          |
 * |...  \ | /  ..  \ | /  ...|
 * |     -----      -----     |
 * |     |TCP|      |UDP|     |
 * |     -----      -----     |
 * |         \      /         |
 * |         --------         |
 * |         |  IP  |         |
 * |  -----  -*----*-  -----  |
 * |  |ARP|   |    |   |ARP|  |
 * |  -----   |    |   -----  |
 * |      \   |    |   /      |
 * |      ------  ------      |
 * |      |ENET|  |ENET|      |
 * |      ---@--  ---@--      |
 * ----------|-------|---------
 *           |       |
 *           |    ---o---------------------------
 *           |   Ethernet Cable 2
 * ----------o----------
 *     Ethernet Cable 1
 * 
 * @author xiehui
 */
public class Tinytcp {
	public static final int SNAPLEN = 65536; // 抓包长度
	public static final int READ_TIMEOUT = 5; // 超时
	public static final int BUFFER_SIZE = 1024*1024; // 缓冲区大小
	public static PcapNetworkInterface nif;
	public static Properties cfg = new Properties();
	public static void main(String[] args) throws Exception {
		cfg.load(Tinytcp.class.getResourceAsStream("tinytcp.cfg"));
		
		// 设置过滤器，参见 wireshark
		String filter = ""; 
		// 选择网络设备
		nif = new NifSelector().selectNetworkInterface();
		System.out.println(nif.getName() + " (" + nif.getDescription() + ")");
		for (PcapAddress addr : nif.getAddresses()) {
			if (addr.getAddress() != null) {
				System.out.println("IP address: " + addr.getAddress());
			}
		}
		System.out.println("");
		
		// 初始化抓包器 采用混杂模式 PROMISCUOUS
		// PcapHandle.Builder phb = new PcapHandle.Builder(nif.getName()).snaplen(SNAPLEN).promiscuousMode(PromiscuousMode.PROMISCUOUS).timeoutMillis(READ_TIMEOUT).bufferSize(BUFFER_SIZE);
		// 设置时间精度
		// phb.timestampPrecision(TimestampPrecision.NANO); 
		// PcapHandle receiveHandle = phb.build();
		
		// 创建接收与发送 hanle
		PcapHandle receiveHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
		PcapHandle sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
		// 采用高性能网络过滤内核模块
		receiveHandle.setFilter(filter, BpfCompileMode.OPTIMIZE);
		// 打开数据链路层
		new DatalinkLayer(receiveHandle,sendHandle).open();	
		
		// 测试发送一个 arp 包
		ARP.sendArpPacket((String)cfg.get("arp.test.srcMac"),(String)cfg.get("arp.test.srcIp"),(String)cfg.get("arp.test.dstIp"));
		
		// 等待5秒
		Thread.sleep(1000*5);
		
		ICMP.sendIcmpPacket((String)cfg.get("arp.test.srcIp"), (String)cfg.get("arp.test.srcMac"), (String)cfg.get("arp.test.dstIp"),ARP.tables.get("/"+(String)cfg.get("arp.test.dstIp")));
	}
}
