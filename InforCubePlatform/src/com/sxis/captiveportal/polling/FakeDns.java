package com.sxis.captiveportal.polling;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.apache.log4j.Logger;
import org.krakenapps.pcap.decoder.ethernet.EthernetFrame;
import org.krakenapps.pcap.decoder.ethernet.MacAddress;
import org.krakenapps.pcap.live.PcapDevice;
import org.krakenapps.pcap.util.Buffer;

import com.sxis.captiveportal.po.FakeDnsResponse;

/**
 * 虚假DNS服务器，所有域名统一解析成本机ip
 * @author KevinXC
 * 2013-6-26
 */
public class FakeDns {
	private final static Logger logger = Logger.getLogger(FakeDns.class.getName());
	private FakeDns() {}

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
	 * 生成一个假的DNS响应报文并发送
	 * @param fakeIp
	 * @param device
	 * @param frame
	 * @param src
	 * @param srcPort
	 * @param dst
	 * @param dstPort
	 * @param buf
	 */
	public static void forgeResponse(InetAddress fakeIp, PcapDevice device, EthernetFrame frame, InetAddress src,
			int srcPort, InetAddress dst, int dstPort, Buffer buf) {
		if (fakeIp == null || device == null)
			return;

		InetSocketAddress source = new InetSocketAddress(src, srcPort);
		InetSocketAddress destination = new InetSocketAddress(dst, dstPort);
		FakeDnsResponse r = getDnsResponse(fakeIp, frame, source, destination, buf);	//获取一个带有虚假ip的DNS相应报文的对象
		if (r != null)
			sendPacket(device, r.getPacket());	//通过相应网卡发送报文

		logger.debug("发送伪造的DNS响应报文, " + destination + " => " + source + ", " + r);
	}

	/**
	 * 发送报文，需要定义PCAP的网卡设备
	 * @param device
	 * @param b
	 */
	private static void sendPacket(PcapDevice device, Buffer b) {
		try {
			device.write(b);
		} catch (IOException e) {
			logger.error("无法发送DNS包 ", e);
		}
	}

	/**
	 * 获取FakeDnsResponse对象
	 * @param fakeIp
	 * @param frame
	 * @param src
	 * @param dst
	 * @param buf
	 * @return
	 */
	private static FakeDnsResponse getDnsResponse(InetAddress fakeIp, EthernetFrame frame, InetSocketAddress src,
			InetSocketAddress dst, Buffer buf) {
		/**
		 * DNS查询报文
		 * 0000 00 19 56 6e 19 bf 00 17 a4 1a b2 e0 08 00 45 00   ..Vn.... ......E.

		 * 0010 00 3b ed c6 00 00 80 11 e3 c3 ac 15 0f 04 ac 15   .;...... ........

		 * 0020 01 f9 04 a9 00 35 00 27 2f bd (3e 3a) (01 00) (00 01)   .....5.' /.>:....
											   txid    flags  查询数量
		 * 0030 (00 00) (00 00) (00 00) (03 77 77 77 06 67 6f 6f 67 6c   .......w ww.googl
				    回答	    授权	     额外		查询域名 www.google.cn
		 * 0040 65 02 63 6e 00) (00 01) (00 01)                        e.cn.... .      
		 *				      type 1-query	class 1-Internet数据
		 */						
		buf.rewind();
		buf.skip(28); // skip length and checksum
		int txId = buf.getUnsignedShort();	//txid 作为DNS请求报文的标识，相应报文必须带同样的txid
		int flags = buf.getUnsignedShort();	//标志位 ip报文的字段
		int questionCount = buf.getUnsignedShort();
		int answerCount = buf.getUnsignedShort();
		int authorityCount = buf.getUnsignedShort();
		int additionalCount = buf.getUnsignedShort();

		// 0x100表示该报文可以被截断
		if (flags != 0x0100)
			return null;

		// 根据字段判断是否为DNS请求报文
		boolean isQuery = (questionCount == 1 && answerCount == 0 && authorityCount == 0 && additionalCount == 0);
		if (!isQuery){
			return null;
		}

		String domain = decodeDomain(buf);	//从报文中解析出DNS请求中的域名
		int type = buf.getUnsignedShort();
		int clazz = buf.getUnsignedShort();
		if (type != 1 || clazz != 1){
			logger.debug("type:" + type + ",clazz:" + clazz);
			return null;
		}
			
		MacAddress targetMac = frame.getSource();
		return new FakeDnsResponse(targetMac, src, dst, (short) txId, domain, fakeIp);
	}

	private static String decodeDomain(Buffer buf) {
		String domain = "";

		while (true) {
			byte length = buf.get();
			if (length == 0)
				break;

			byte[] b = new byte[length];
			buf.gets(b);

			String token = new String(b);
			if (domain.length() == 0)
				domain += token;
			else
				domain += "." + token;
		}

		logger.debug("DNS报文中解析出来的域名为："+domain);
		return domain;
	}
}
