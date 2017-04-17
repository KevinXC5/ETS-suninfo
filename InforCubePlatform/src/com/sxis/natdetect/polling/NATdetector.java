/**
 * 
 */
package com.sxis.natdetect.polling;

import java.net.InetAddress;
import java.util.HashMap;

import org.apache.log4j.Logger;
import org.krakenapps.pcap.decoder.ethernet.EthernetFrame;
import org.krakenapps.pcap.decoder.ethernet.MacAddress;
import org.krakenapps.pcap.decoder.ip.Ipv4Packet;
import org.krakenapps.pcap.util.Buffer;

import com.sxis.natdetect.po.IlicitNAT;
import com.sxis.natdetect.po.TriggerThread;

/**
 * 非法NAT设备检测 底层平台-原理解析ip数据报
 * @author KevinXC
 * 2014-1-14
 */
public class NATdetector{
	private final static Logger logger = Logger.getLogger(NATdetector.class.getName());
	private static HashMap<String, IlicitNAT> ilicitNATs = new HashMap<String, IlicitNAT>();
	
	public void process(Buffer buf, EthernetFrame frame, InetAddress src, MacAddress srcmac,
			InetAddress dst, MacAddress dstmac, int srcPort, int dstPort, int protocol) {
		//以太网帧封装成ip报文
		buf.rewind();
		Ipv4Packet packet = Ipv4Packet.parse(buf);
		packet.setL2Frame(frame);
		
//		logger.debug(packet.toString());
		logger.info(src.getHostAddress() + " (" + srcmac + ")" + " > " + dst.getHostAddress() + " (" + dstmac + ")"
				+ " scrPort : " + srcPort + " dstPort : " + dstPort + " protocol : " + protocol + " id ：" + packet.getId() + " ttl : " + packet.getTtl() 
				+ " version : " + packet.getVersion() + " flag : " + packet.getFlags());
		
		//列表里没有此ip报文信息，则需要添加到列表里
		if (!ilicitNATs.containsKey(src.getHostAddress())) {
			IlicitNAT in = new IlicitNAT(src.getHostAddress(), packet.getTtl(), packet.getId(), false);
			ilicitNATs.put(src.getHostAddress(), in);
			logger.info(src + " 添加成功，当前 map 大小为：" + ilicitNATs.size());
			return;
		}
		
		//判断当前ttl的值是否和之前的一致，如果不一致则确定为NAT
		IlicitNAT nat = ilicitNATs.get(src.getHostAddress());
		
		int idMinus = Math.abs(packet.getId() - nat.getLastId());
		logger.info("idminus " + idMinus);
	
		//先将最新的id赋值到对象
		nat.setLastId(packet.getId());
		
		//连续的两个id相差小于一定值，表明同一太终端发出，不处理
		if (idMinus <= 500) {
			return;
		}
		
		/*
		 * 判断是否为NAT
		 * NAT初始ttl为64，终端 初始ttl分别为64、128、255时，如果abs为 1、63、190则为NAT
		 * NAT初始ttl为128，终端 初始ttl分别为64、128、255时，如果abs为 65、1、126则为NAT
		 * NAT初始ttl为255，终端 初始ttl分别为64、128、255时，如果abs为 192、128、1则为NAT
		 */
		int abs = Math.abs(packet.getTtl() - nat.getTtl());
		if (abs == 1 || abs == 63 || abs == 65 || 
				abs == 126 || abs == 128 || abs == 190 || abs == 192 ) {
			logger.info("报文ttl差值为 " + abs);
			//之前此设备未被发现为NAT，则进行处理
			if (!nat.isNAT()) {
				markAsNAT(nat);
			}
		}
		
//		int i = 0;
//		List<String> natList = new ArrayList<String>();
//		for (Entry<String, IlicitNAT> entry : ilicitNATs.entrySet()) {
//			if (entry.getValue().isNAT()) {
//				i++;
//				natList.add(entry.getKey());
//			}
//			
//			logger.info(entry.getKey() + " : " + entry.getValue().getIp() + " - " + entry.getValue().getLastId() + " - " + entry.getValue().getTtl()
//					+ " - " + entry.getValue().isNAT());
//		}
//		
//		logger.info("Total: " + ilicitNATs.size());
//		logger.info("NAT: " + i);
//		
//		for (String s : natList) {
//			logger.info(s + " : " + ilicitNATs.get(s).getIp() + " - " + ilicitNATs.get(s).getLastId() + " - " + ilicitNATs.get(s).getTtl()
//					+ " - " + ilicitNATs.get(s).isNAT());
//		}
		
//		updateMap(nat);
	}
	
	/**
	 * 将设备标记为NAT，包括更改map中状态以及查出对应mac地址进行数据库操作
	 * @param nat
	 */
	public void markAsNAT(IlicitNAT nat) {
		logger.info(nat.getIp() + " 发出的报文出现多个ttl值，确定其为NAT设备，触发违规");
		nat.setNAT(true);
		
		//使用线程触发违规，提高效率
		Thread t = new Thread(new TriggerThread(nat));
		t.start();
	}

	/**
	 * 将设备标记为NAT，包括更改map中状态以及查出对应mac地址进行数据库操作
	 * @param nat
	 */
	public void updateMap(IlicitNAT nat) {
		ilicitNATs.remove(nat.getIp());
		ilicitNATs.put(nat.getIp(), nat);
	}

	/**
	 * 判断是否为DNS报文
	 * @param protocol (tcp 6 , udp 17)
	 * @param dstPort
	 * @return
	 */
	public static boolean isDnsPacket(int protocol, int dstPort) {
		return protocol == 17 && dstPort == 53;  	// UDP协议为17，DNS报文使用53端口
	}
}
