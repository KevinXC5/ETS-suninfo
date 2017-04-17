package com.sxis.captiveportal.polling;

import java.io.IOException;
import java.net.InetAddress;
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
import org.krakenapps.pcap.live.PcapDevice;
import org.krakenapps.pcap.live.PcapDeviceManager;
import org.krakenapps.pcap.packet.PcapPacket;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.IpConverter;

import com.sxis.biz.sysconf.util.License;
import com.sxis.biz.util.ConfFileUtil;
import com.sxis.captiveportal.discoveryservice.CaptivePortal;
import com.sxis.captiveportal.util.CaptivePortalStarter;
import com.sxis.natdetect.polling.NATdetector;

/**
 * 虚假路由器（线程类）-用以接收以太网报文，并处理DNS报文
 * @author KevinXC
 * 2013-6-27
 */
public class FakeRouter implements Runnable, EthernetProcessor {
	private static final Logger logger = Logger.getLogger(FakeRouter.class.getName());
	
	private static ThreadPoolExecutor pool;				// 处理以太网报文的线程池
	private static final int POOL_CORE_SIZE = 50;		// 核心线程数
	private static final int POOL_MAX_SIZE = 200;		// 最大线程数
	private static final int KEEP_ALIVE_TIME = 2000;	// 单个线程保活时间 （毫秒）
	private static final int QUEUE_SIZE = 100;			// 等待队列大小
	
	private Thread t;
	private PcapDevice device;
	private volatile boolean doStop;

	private MacAddress localmac;
	private CaptivePortal portal;
	
	public FakeRouter(String deviceName, CaptivePortal portal) throws IOException {
		this.device = PcapDeviceManager.open(deviceName, 1000000);
		this.localmac = device.getMetadata().getMacAddress();
		this.portal = portal;
	}

	/**
	 * 启动线程
	 */
	public void start() {
		initThreadPool();
		t = new Thread(this, "Fake Router");
		t.start();	//线程类start, 执行run方法
	}

	/**
	 * 停止线程
	 */
	public void stop() {
		try {
			doStop = true;
			t.interrupt();
			device.close();	//关闭接收报文的网卡设备
		} catch (IOException e) {
			logger.error("无法关闭网卡设备 ", e);
		}
	}

	@Override
	public void run() {
		//监听并解析IPv4的以太网报文
		EthernetDecoder eth = new EthernetDecoder();
		eth.register(EthernetType.IPV4, this);

		doStop = false;

		try {
			while (!doStop) {
				PcapPacket packet = device.getPacket();		// 获取网卡设备的数据包
				
				MultiThreadProcessor processor = new MultiThreadProcessor(eth, packet);
				pool.execute(processor);	// 线程池处理
//				eth.decode(packet);		//解析包，并将包分发给每个proccessor，相应的执行process方法
			}
		} catch (IOException e) {
			logger.error("解析IPv4报文时io异常 ", e);
		} finally {
			logger.info("虚假路由器已停止 ");
			CaptivePortalStarter.stopIfence();
		}
	}

	@Override
	/**
	 * IP数据报格式：
	 * 0                          15 16                           31
	 * |———————————————————————————————————————————————————————————|     ——
	 * |  4位     | 4位    | 8位服务类型       |     16位总长度(字节数)       　　　|      |
	 * |  版本   | 长度 |   (TOS)      |                              |      |                  
	 * |———————————————————————————————————————————————————————————|      |
	 * |          16位标识                            | 3位     |     　　　13位偏移                       |      |
	 * |                            | 标志  |                        |      |                        
	 * |———————————————————————————————————————————————————————————|      20
	 * | 8位生存时间    |    8位协议          |        16位首部校验和                       |      字
	 * |   (TTL)     |              |                              |      节                  
	 * |———————————————————————————————————————————————————————————|	  |
	 * |                      32位源IP地址                                                                    |      |
	 * |                                                           |      |                 
	 * |———————————————————————————————————————————————————————————|      |
	 * |                     32位目的IP地址                                                                  |      |
	 * |                                                           |      |                        
	 * |———————————————————————————————————————————————————————————|     ——
	 * |                      选项(如果有)                          |
	 * |                                                           |                        
	 * |———————————————————————————————————————————————————————————|
	 * |                          数据                                                                              |
	 * |                                                           |                        
	 * |———————————————————————————————————————————————————————————|
	 *                        
	 */
	public void process(EthernetFrame frame) {
		Buffer buf = frame.getData();
		buf.skip(9);
		int protocol = buf.get();	//获取报文协议
		buf.skip(2);

		//获取报文源、目的ip和端口
		InetAddress src = IpConverter.toInetAddress(buf.getInt());
		InetAddress dst = IpConverter.toInetAddress(buf.getInt());
		int srcPort = buf.getUnsignedShort();
		int dstPort = buf.getUnsignedShort();

		if (dst.isMulticastAddress())
			return;

		buf.rewind();
		byte[] b = new byte[buf.readableBytes() + 14];
		buf.gets(b, 14, b.length - 14);
		b[12] = 0x08;
		b[13] = 0x00;

		MacAddress srcmac = frame.getSource();			//报文源mac
		MacAddress dstmac = frame.getDestination();		//报文目的mac
		InetAddress redirectIp = portal.getRedirectAddress();

		MacAddress gwmac = portal.getGatewayMacAddress();
//		logger.debug(src.getHostAddress() + " (" + srcmac + ")" + " > " + dst.getHostAddress() + " (" + dstmac + ")"
//				+ " scrPort : " + srcPort + " dstPort : " + dstPort + " protocol : " + protocol);
		
		if (gwmac == null) {
			logger.error("网关地址为空，返回！");
			return;
		}

		//收到的报文为DNS报文，进行处理
		if (FakeDns.isDnsPacket(protocol, dstPort)) {
			logger.debug("处理DNS报文...");
				
			// 报文源mac地址为本机或者不是网关，目的ip为本机，不作处理！
//			if (srcmac.equals(localmac) || !srcmac.equals(gwmac) || dst.equals(redirectIp)) {
			if (srcmac.equals(localmac) || dst.equals(redirectIp)) {
				logger.debug("报文源mac地址为本机，不作处理！");
				return;
			}
			
			//根据ip获取mac授权状态，如果为空则需要欺骗
			MacAddress asrcmac = portal.getAuthorizedMac(src);
				
			// 源mac不存在或者未认证，接收DNS报文，丢弃其他报文
			if (asrcmac == null) {
				logger.debug("srcip : " + src + " srcmac : " + srcmac + " srcport ：" + srcPort + " dstip : " + dst 
						+ " dstmac : " + dstmac + " dstport : " + dstPort + " asrcmac : " + asrcmac + " gwmac : " + gwmac);
				
				// 伪造dns相应报文，并发送给终端
				FakeDns.forgeResponse(portal.getRedirectAddress(), device, frame, src, srcPort, dst, dstPort, buf);
			}
			
//			if ("standard".equals(ConfFileUtil.MAC_MODE) 
//					&& License.modules.get("VIOLATION_PORTBIND")) {//将报文发给NAT检测器检测
//				NATdetector detection = new NATdetector();
//				detection.process(buf, frame, src, asrcmac, dst, dstmac, srcPort, dstPort, protocol);
//			}
			
		}
//		else {	// 源mac已认证，转发报文(替换 src mac -> local mac , dst mac -> gateway mac)
//			logger.debug(asrcmac + " 已认证，转发报文");
//			byte[] d = gwmac.getBytes();
//			for (int i = 0; i < 6; i++)
//				b[i] = d[i];
//
//			byte[] s = localmac.getBytes();
//			for (int i = 0; i < 6; i++)
//				b[i + 6] = s[i];
//
//			sendPacket(b);
//		}
	}

	/**
	 * 发送报文，需要定义PCAP的网卡设备
	 * @param b
	 */
	@SuppressWarnings("unused")
	private void sendPacket(byte[] b) {
		try {
			device.write(b);
		} catch (IOException e) {
			logger.error("转发报文出错  ", e);
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
