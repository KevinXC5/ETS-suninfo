package com.sxis.natdetect.test;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;
import org.krakenapps.pcap.decoder.ethernet.EthernetDecoder;
import org.krakenapps.pcap.decoder.ethernet.EthernetFrame;
import org.krakenapps.pcap.decoder.ethernet.EthernetProcessor;
import org.krakenapps.pcap.decoder.ethernet.EthernetType;
import org.krakenapps.pcap.decoder.ethernet.MacAddress;
import org.krakenapps.pcap.decoder.ip.Ipv4Packet;
import org.krakenapps.pcap.live.PcapDevice;
import org.krakenapps.pcap.live.PcapDeviceManager;
import org.krakenapps.pcap.live.PcapDeviceMetadata;
import org.krakenapps.pcap.packet.PcapPacket;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.IpConverter;

import com.sxis.captiveportal.discoveryservice.impl.CaptivePortalService;
import com.sxis.captiveportal.polling.FakeRouter;
import com.sxis.natdetect.po.IlicitNAT;

public class PacketCapture implements EthernetProcessor{
	static String ip = "";
	private static PcapDevice device = null;
	private static HashMap<String, IlicitNAT> ilicitNATs = new HashMap<String, IlicitNAT>();
	private static boolean flag = true;
	private static MacAddress localMac;
	
	private static ThreadPoolExecutor pool;				// 处理以太网报文的线程池
	private static final int POOL_CORE_SIZE = 50;		// 核心线程数
	private static final int POOL_MAX_SIZE = 200;		// 最大线程数
	private static final int KEEP_ALIVE_TIME = 2000;	// 单个线程保活时间 （毫秒）
	private static final int QUEUE_SIZE = 100;			// 等待队列大小
	
	public void run() throws IOException, InterruptedException {
		initThreadPool();
		
		//打开网卡设备
		for (PcapDeviceMetadata metadata : PcapDeviceManager.getDeviceMetadataList()) {
			System.out.println(metadata.toString());
			if (metadata.getName().startsWith("eth2")) {
				System.out.println("open device: " + metadata.toString());
				device = PcapDeviceManager.open(metadata.getName(), 1000000);
				localMac = device.getMetadata().getMacAddress();
				System.out.println("--------------------------------localMac: " + localMac);
			}
		}
		
//		for (PcapDeviceMetadata metadata : PcapDeviceManager.getDeviceMetadataList()) {
//			System.out.println(metadata.toString());
//			if (metadata.getDescription().startsWith("Realtek")) {
//				System.out.println("open device: " + metadata.toString());
//				device = PcapDeviceManager.open(metadata.getName(), 1000000);
//			}
//		}
		
		//注册分析ipv4报文的解码器
		EthernetDecoder ethDecoder = new EthernetDecoder();
		ethDecoder.register(EthernetType.IPV4, this);
		
		//从device获取报文并解码
		while (flag) {
			PcapPacket packet = device.getPacket();
			
			MultiThreadProcessor processor = new MultiThreadProcessor(ethDecoder, packet);
			pool.execute(processor);	// 线程池处理
			
			ethDecoder.decode(packet);
			
		}
		
	}
	
	/**
	 * 初始化线程池
	 */
	private static void initThreadPool() {
		BlockingQueue<Runnable> workQueue = new ArrayBlockingQueue<Runnable>(QUEUE_SIZE);
		pool = new ThreadPoolExecutor(POOL_CORE_SIZE, POOL_MAX_SIZE, KEEP_ALIVE_TIME, TimeUnit.MICROSECONDS, workQueue, new ThreadPoolExecutor.DiscardOldestPolicy());
		Logger logger = Logger.getLogger(FakeRouter.class.getName());
		logger.info("以太网报文解析线程池启动...");
	}
	
	@Override
	public void process(EthernetFrame frame) {
		
		Buffer buf = frame.getData();
		buf.skip(9);
		int protocol = buf.get();	//获取报文协议   ICMP - 1 , TCP - 6 , UDP - 17
		buf.skip(2);

		//获取报文源、目的ip和端口
		int srcIp = buf.getInt();
		int dstIp = buf.getInt();
		InetAddress src = IpConverter.toInetAddress(srcIp);
		InetAddress dst = IpConverter.toInetAddress(dstIp);
		int srcPort = buf.getUnsignedShort();
		int dstPort = buf.getUnsignedShort();
		
//		buf.skip(9);
//		int flag = buf.get();

		if (dst.isMulticastAddress())
			return;

		//buf索引恢复到初始位置
		buf.rewind();
		byte[] b = new byte[buf.readableBytes() + 14];
		buf.gets(b, 14, b.length - 14);
//		b[12] = 0x08;
//		b[13] = 0x00;

		MacAddress srcmac = frame.getSource();			//报文源mac
		MacAddress dstmac = frame.getDestination();		//报文目的mac
//		String domain = FakeDns.decodeDomain(buf);
		MacAddress asrcmac = new CaptivePortalService().getAuthorizedMac(src);
		
		if((!src.getHostAddress().startsWith(ip)))
			return;
		
		int i = 0;
		if (!srcmac.equals(localMac) && isDnsPacket(protocol, dstPort)) {
			System.out.println("处理DNS报文... srcmac: " + srcmac);
			process(buf, frame, src, asrcmac, dst, dstmac, srcPort, dstPort, protocol);
			
			List<String> natList = new ArrayList<String>();
			for (Entry<String, IlicitNAT> entry : ilicitNATs.entrySet()) {
				if (entry.getValue().isNAT()) {
					i++;
					natList.add(entry.getKey());
				}
				
				System.out.println(entry.getKey() + " : " + entry.getValue().getIp() + " - " + entry.getValue().getLastId() + " - " + entry.getValue().getTtl()
						+ " - " + entry.getValue().isNAT());
			}
			
			System.err.println("Total: " + ilicitNATs.size());
			System.err.println("NAT: " + i);
			
			for (String s : natList) {
				System.out.println(s + " : " + ilicitNATs.get(s).getIp() + " - " + ilicitNATs.get(s).getLastId() + " - " + ilicitNATs.get(s).getTtl()
						+ " - " + ilicitNATs.get(s).isNAT());
			}
		}
	}
	
	public void process(Buffer buf, EthernetFrame frame, InetAddress src, MacAddress srcmac,
			InetAddress dst, MacAddress dstmac, int srcPort, int dstPort, int protocol) {
		
		//以太网帧封装成ip报文
		buf.rewind();
		Ipv4Packet packet = Ipv4Packet.parse(buf);
		packet.setL2Frame(frame);
		
//		logger.debug(packet.toString());
		System.out.println(src.getHostAddress() + " (" + srcmac + ")" + " > " + dst.getHostAddress() + " (" + dstmac + ")"
				+ " scrPort : " + srcPort + " dstPort : " + dstPort + " protocol : " + protocol + " id ：" + packet.getId() + " ttl : " + packet.getTtl() 
				+ " version : " + packet.getVersion() + " flag : " + packet.getFlags());
		
		//列表里没有此ip报文信息，则需要添加到列表里
		if (!ilicitNATs.containsKey(src.getHostAddress())) {
			IlicitNAT in = new IlicitNAT(src.getHostAddress(), packet.getTtl(), packet.getId(), false);
			ilicitNATs.put(src.getHostAddress(), in);
			System.out.println(src + " 添加成功，当前 map 大小为：" + ilicitNATs.size());
			return;
		}
		
		//判断当前ttl的值是否和之前的一致，如果不一致则确定为NAT
		IlicitNAT nat = ilicitNATs.get(src.getHostAddress());
		
		int idMinus = Math.abs(packet.getId() - nat.getLastId());
		System.out.println("idminus " + idMinus);
		
		//先将最新的id赋值到对象
		nat.setLastId(packet.getId());
		//连续的两个id相差小于一定值，表明同一太终端发出，不处理
		if (idMinus <= 500) {
			return;
		}
		
		/*
		 * 判断是否为NAT
		 * NAT初始ttl为64，终端 初始ttl分别为64、128时，如果abs为 1、63则为NAT
		 * NAT初始ttl为128，终端 初始ttl分别为64、128时，如果abs为 65、1则为NAT
		 */
		int abs = Math.abs(packet.getTtl() - nat.getTtl());
		System.out.println("abs :" + abs);
		if (abs == 1 || abs == 63 || abs == 65) {
			//之前此设备未被发现为NAT，则进行处理
			if (!nat.isNAT()) {
				markAsNAT(nat);
			}
		}
//		updateMap(nat);
	}
	
	
	/**
	 * 将设备标记为NAT，包括更改map中状态以及查出对应mac地址进行数据库操作
	 * @param nat
	 */
	public void markAsNAT(IlicitNAT nat) {
		System.out.println(nat.getIp() + " 发出的报文出现多个ttl值，确定其为NAT设备，触发违规");
		nat.setNAT(true);
//		flag = false;
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
	 * @param args
	 * @throws IOException 
	 * @throws InterruptedException 
	 */
	public static void main(String[] args) throws IOException, InterruptedException {
		ip = args[0];
		new PacketCapture().run();
		
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
	
	/**
	 * 多线程处理器-调用EthernetDecoder来处理DNS报文（内部类）
	 * @author KevinXC
	 * 2013-6-27
	 */
	class MultiThreadProcessor implements Runnable {
		private EthernetDecoder eth;
		private PcapPacket packet;
		
		public MultiThreadProcessor() {
			super();
		}

		public MultiThreadProcessor(EthernetDecoder eth, PcapPacket packet) {
			super();
			this.eth = eth;
			this.packet = packet;
		}

		@Override
		public void run() {
			// 解析包，并将包分发给每个EthernetProccessor，执行相应的process方法
			this.eth.decode(this.packet);
		}
	}
	
}
