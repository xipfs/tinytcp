package net.xipfs.tinytcp.datalinklayer;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.EthernetPacket.EthernetHeader;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.EtherType;

import net.xipfs.tinytcp.datalinklayer.protocol.ARP;
import net.xipfs.tinytcp.networklayer.NetworkLayer;

/**
 * 数据链路层
 * 
 * 
 *Ethernet II帧格式：
 *---------------------------------------------------------------------------------------------- 
 *|   前序   | 目的地址 | 源地址  |   类型  |    数据       |  FCS  |
 *----------------------------------------------------------------------------------------------
 *| 8 byte  | 6 byte  | 6 byte | 2 byte | 46~1500 byte | 4 byte|
 *----------------------------------------------------------------------------------------------
 * @author xiehui
 */
public class DatalinkLayer {
	private PcapHandle receiveHandle;
	private PcapHandle sendHandle;
	private static BlockingQueue<Packet> queue = new LinkedBlockingQueue<Packet>();
	private NetworkLayer networklayer = new NetworkLayer();
	public DatalinkLayer(PcapHandle receiveHandle, PcapHandle sendHandle) {
		this.receiveHandle = receiveHandle;
		this.sendHandle = sendHandle;
	}
	
	public void open() {
		// 接收数据线程
		new Thread() {
			@Override
			public void run() {
				// 注册处理数据包协议
				System.out.println("准备从网卡获取数据");
				while (true) {
					try {
						Packet packet = receiveHandle.getNextPacket();
						if (packet == null) {
							continue;
						} else {
							receivePacket(packet);
						}
					}catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		}.start();
		
		// 发送数据线程
		new Thread() {
			@Override
			public void run() {
				System.out.println("准备向网卡发送数据");
				while(true) {
					sendPacket();
				}
			}
		}.start();
	}
	// 数据链路层以太网帧头长度 目的地址(6) + 源地址(6) + 类型(2) = 14 byte
	public static final int EthernetHeaderLength  = 14;
	public void receivePacket(Packet packet) throws Exception {
		EthernetPacket epacket = (EthernetPacket)packet;
		EthernetHeader eheader = epacket.getHeader();
		if(eheader.getType().compareTo(EtherType.ARP) == 0) {
			// arp 消息在数据链路层处理
			new ARP().analyze(epacket);
		}else if(eheader.getType().compareTo(EtherType.IPV4) == 0) {
			// 交给网络层分析消息
			networklayer.analyze(packet);
		}else {
			System.out.println(packet);
		}
	}
	public void sendPacket(){
		try {
			Packet packet = queue.take();
			sendHandle.sendPacket(packet);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void addPacket(Packet packet) {
		queue.offer(packet);
	}
}
