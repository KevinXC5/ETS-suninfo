package com.sxis.captiveportal.discoveryservice;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Map;

import org.krakenapps.pcap.decoder.ethernet.MacAddress;

/**
 * 基于DNS的Portal重定向接口
 * @author KevinXC
 * 2013-6-24
 */
public interface CaptivePortal {
	
	/**
	 * 获取重定向ip
	 * @return
	 */
	InetAddress getRedirectAddress();
	
	/**
	 * 设置重定向ip
	 * @param ip
	 */
	void setRedirectAddress(InetAddress ip);
	
	/**
	 * 获取arpCache
	 * @return
	 */
	Map<InetAddress, MacAddress> getArpCache();

	/**
	 * 获取传入的ip对应mac是否为已认证状态
	 * @param ip
	 * @return null - 未认证， 非null - 已认证
	 */
	MacAddress getAuthorizedMac(InetAddress ip);
	
	/**
	 * 获取设置的PCAP网卡设备
	 * @return
	 */
	String getPcapDeviceName();

	/**
	 * 设置PCAP网卡设备，并且需要重启fake router
	 * @param name
	 */
	void setPcapDeviceName(String name);

	/**
	 * 获取arp表同步周期
	 * @return
	 */
	int getArpInterval();

	/**
	 * 设置arp表同步周期
	 * @param milliseconds
	 */
	void setArpInterval(int milliseconds);

	/**
	 * 获取网关交换机 mac 地址
	 * @return
	 */
	MacAddress getGatewayMacAddress();

	/**
	 * 获取网关交换机ip地址
	 * @return
	 */
	InetAddress getGatewayAddress();

	/**
	 * 设置网关交换机ip地址
	 * @param address
	 */
	void setGatewayAddress(InetAddress address);

	/**
	 * 定期同步交换机arp表到本地iplog
	 * @throws IOException
	 */
	void arpSync() throws IOException;
}
