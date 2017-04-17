package com.sxis.captiveportal.discoveryservice.impl;

import java.io.IOException;
import java.net.InetAddress;
import java.sql.SQLException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.prefs.BackingStoreException;

import org.apache.log4j.Logger;
import org.krakenapps.pcap.decoder.ethernet.MacAddress;
import org.krakenapps.pcap.util.Arping;

import com.sxis.biz.baseinfo.devicemanage.manage.INodeBiz;
import com.sxis.biz.baseinfo.devicemanage.manage.impl.NodeBizImpl;
import com.sxis.biz.baseinfo.devicemanage.po.Node;
import com.sxis.biz.baseinfo.devicemanage.util.PingUtil;
import com.sxis.biz.baseinfo.iplog.manage.IIpLogBiz;
import com.sxis.biz.baseinfo.iplog.manage.impl.IpLogBizImpl;
import com.sxis.biz.baseinfo.iplog.po.Iplog;
import com.sxis.biz.baseinfo.paramconfig.manage.IFilterdeviceBiz;
import com.sxis.biz.baseinfo.paramconfig.manage.impl.FilterdeviceBizImpl;
import com.sxis.biz.baseinfo.paramconfig.po.Filterdevice;
import com.sxis.biz.common.dao.HibernateSessionFactory;
import com.sxis.biz.manage.util.ArpUtil;
import com.sxis.biz.util.ConfFileUtil;
import com.sxis.captiveportal.discoveryservice.CaptivePortal;
import com.sxis.captiveportal.polling.FakeRouter;
import com.sxis.captiveportal.util.CaptivePortalStarter;

/**
 * CaptivePortal实现类-线程类
 * @author KevinXC
 * 2013-6-25
 */
public class CaptivePortalService implements CaptivePortal, Runnable {
	private static final String REDIRECT_IP_KEY = "redirect_ip";
	private static final String PCAP_DEVICE_KEY = "pcap_device";
	private static final int ARP_TIMEOUT = 3000;
	private static final String ARP_INTERVAL_KEY = "arp_interval";
	private static final String GATEWAY_KEY = "gateway";

	private final static Logger logger = Logger.getLogger(CaptivePortalService.class.getName());

	private String deviceName;				//PCAP网卡设备
	private InetAddress redirectAddress;	//重定向ip地址
	private InetAddress gatewayAddress;		//网关ip
	private MacAddress gatewayMac;			//网关mac

	private int arpInterval;
	private FakeRouter fakeRouter;

	// arp 查询线程
	private Thread arpThread;
	private volatile boolean doStop;

	// ip-mac 缓存
	private Map<InetAddress, IpMapping> arpCache;
	// 存放一些核心配置项的map
	private Map<String, String> root = new HashMap<String, String>();

	/**
	 * CaptivePortal 服务启动方法-初始化变量、开启Fake Router和ARP Searcher
	 * @throws BackingStoreException
	 * @throws IOException
	 */
	public void start() throws BackingStoreException, IOException {
		logger.info("Captive Portal 服务启动...");
		
		arpCache = new ConcurrentHashMap<InetAddress, IpMapping>();		//初始化一个arp表缓存的对象
		
		String redirectIp = root.get(REDIRECT_IP_KEY);
		if (redirectIp != null)
			this.redirectAddress = InetAddress.getByName(redirectIp);

		this.gatewayAddress = InetAddress.getByName(root.get(GATEWAY_KEY));
		
		this.deviceName = root.get(PCAP_DEVICE_KEY);
		if (deviceName != null) {
			// 启动 Fake Router
			fakeRouter = new FakeRouter(deviceName, this);
			fakeRouter.start();
			logger.info("Fake Router 启动...");
			
		} else {
			logger.error("未选择网卡， Fake Router 启动失败!");
			CaptivePortalStarter.stopIfence();
			return;
		}

		// 启动 arp 查询器
		startArpSearcher();
		logger.info("arp 线程启动...");
	}

	/**
	 * 停止CaptivePortal服务（关闭arp查询器、关闭虚拟路由器）
	 */
	public void stop() {
		stopArpSearcher();
		fakeRouter.stop();
	}

	/**
	 * 启动arp线程
	 */
	private void startArpSearcher() {
		doStop = false;
		arpThread = new Thread(this, "ARP Searcher");
		arpThread.start();
	}

	/**
	 * 停止arp线程
	 */
	private void stopArpSearcher() {
		doStop = true;
		arpThread.interrupt();
	}
	
	@Override
	public InetAddress getRedirectAddress() {
		return redirectAddress;
	}

	@Override
	public void setRedirectAddress(InetAddress ip) {
		root.put(REDIRECT_IP_KEY, ip.getHostAddress());
		this.redirectAddress = ip;
	}

	@Override
	public Map<InetAddress, MacAddress> getArpCache() {
		Map<InetAddress, MacAddress> m = new HashMap<InetAddress, MacAddress>();
		for (InetAddress ip : arpCache.keySet()) {
			IpMapping mapping = arpCache.get(ip);
			m.put(ip, mapping.mac);
		}

		return m;
	}

	@Override
	public MacAddress getAuthorizedMac(InetAddress ip) {
		MacAddress authMac = null;
		String mac = null;
		
		try {
			IIpLogBiz ipLogBiz = new IpLogBizImpl();
			Iplog ipLog = ipLogBiz.ip2Mac(ip.getHostAddress());// 根据ip查找iplog对象
			
			//iplog对象存在，并且ip的状态为未认证，才做处理
			if (ipLog != null) {
				if ("noMac".equals(ConfFileUtil.MAC_MODE)) {// 无mac模式直接使用ip作为id
					mac = ipLog.getId().getIp();
				} else {
					mac = ipLog.getId().getMac();
				}
				logger.debug("iplog查询: "+ip.getHostAddress() + " - "+ mac);
				
				INodeBiz deviceBiz = new NodeBizImpl();
				Node node = deviceBiz.getNodeByMAC(mac);// 根据ip获取node对象
				
				if (node != null && "已认证".equals(node.getStatus())) {
					logger.debug("终端 " +mac+ " 已认证，不需要进行欺骗");
					authMac = ("noMac".equals(ConfFileUtil.MAC_MODE))? 
							new MacAddress("FF:FF:FF:FF:FF:FF") : new MacAddress(mac);
				} else {
					logger.debug("终端 " +mac+ " 未认证，需要进行欺骗");
				}
			} else {
				logger.debug("iplog表中未查找到 " + ip.getHostAddress() +" 需要欺骗");
			}
			
			// 终端未检测或者未认证但属于终端例外，则不欺骗
			if (authMac == null && isExcludeNode(ip)) {
				authMac = ("noMac".equals(ConfFileUtil.MAC_MODE))? 
						new MacAddress("FF:FF:FF:FF:FF:FF") : new MacAddress(mac);
			}
		} catch (Exception e) {
			logger.error("验证终端认证状态时异常 ", e);
		} finally {
			HibernateSessionFactory.closeSession();//关闭session
		}
		
		return authMac;
	}
	
	/**
	 * 判断是否存在终端例外
	 * @param src
	 * @return
	 */
	private boolean isExcludeNode(InetAddress src) {
		//判断源ip是否属于终端例外，若是则返回不做处理
		IFilterdeviceBiz fBiz = new FilterdeviceBizImpl();
		List<Filterdevice> fDevices = fBiz.findAll();
		// 迭代判断ip是否属于某个终端例外
		for (Filterdevice filterdevice : fDevices) {
			if ("MAC地址".equals(filterdevice.getType())) {
				continue;
			}
			
			boolean isInclude = PingUtil.ipIsInNetSegment(src.getHostAddress(), filterdevice.getIp(), filterdevice.getMask());
			
			if (isInclude) {
				logger.debug(src.getHostAddress() + " 属于终端例外 " + filterdevice.getIp() 
						+ "/" + filterdevice.getMask() + " 不做处理，返回");
				return true;
			}
		}
		
		//判断源ip对应的终端是否属于终端例外
		boolean macIsExlude = PingUtil.macIsExclude(src.getHostAddress());
		if (macIsExlude) {
			logger.debug(src.getHostAddress() + " 对应的mac属于终端例外不做处理，返回");
			return true;
		}
		
		return false;
	}
	
	@Override
	public void run() {
		while (!doStop) {
			try {
				if (deviceName != null) arpSync();	// 同步交换机arp表
				
			} catch (IOException e) {
				logger.error("arp IO错误 ", e);
			} catch (Exception e) {
				logger.error("arp 线程错误 ", e);
			} finally {
				try {
					Thread.sleep(arpInterval);
				} catch (InterruptedException e) {
					logger.error("休眠arp线程时出错", e);
				}
			}
		}
	}

	@Override
	public void arpSync() throws IOException {
		// ensure gateway mac address
		MacAddress mac = Arping.query(gatewayAddress, ARP_TIMEOUT);
		
		if (mac==null) {
			logger.info("arp报文无法获取到 " + gatewayAddress + " 对应的mac地址,从交换机中直接获取");
			IIpLogBiz ipLogBiz = new IpLogBizImpl();
			Iplog ipLog;
			try {
				ipLog = ipLogBiz.ip2Mac(gatewayAddress.getHostAddress());
				
				if (ipLog != null) {
					logger.info("从交换机中获取到 " + gatewayAddress + " 对应mac地址 " + ipLog.getId().getMac());
					mac = new MacAddress(ipLog.getId().getMac());
				}
			} catch (SQLException e) {
				logger.error("查询 iplog 信息异常 ", e);
			}
		}
		
		arpCache.put(gatewayAddress, new IpMapping(mac));
		logger.info("网关 "+gatewayAddress+ " - "+mac+"存入arpCache");
		gatewayMac = arpCache.get(gatewayAddress).mac;

		//TODO 同步网关交换机的arp表到本地iplog表
		logger.info("同步交换机 arp 表到本地 iplog...");
		ArpUtil arputil = new ArpUtil();
		try {
			arputil.getArp();
		} catch (Exception e) {
			logger.error("调用Biz层 ArpUtil 出错", e);
		}
	}

	@Override
	public String getPcapDeviceName() {
		return deviceName;
	}

	@Override
	public void setPcapDeviceName(String name) {
		root.put(PCAP_DEVICE_KEY, name);
		this.deviceName = name;
	}

	@Override
	public int getArpInterval() {
		return arpInterval;
	}

	@Override
	public void setArpInterval(int milliseconds) {
		String interval = String.valueOf(milliseconds);
		root.put(ARP_INTERVAL_KEY, interval);

		this.arpInterval = milliseconds;
	}

	@Override
	public MacAddress getGatewayMacAddress() {
		return gatewayMac;
	}

	@Override
	public InetAddress getGatewayAddress() {
		return gatewayAddress;
	}

	@Override
	public void setGatewayAddress(InetAddress address) {
		root.put(GATEWAY_KEY, address.getHostAddress());

		this.gatewayAddress = address;
	}

	private static class IpMapping {
		private MacAddress mac;
		@SuppressWarnings("unused")
		private Date updated;

		public IpMapping(MacAddress mac) {
			this.mac = mac;
			this.updated = new Date();
		}
	}
}
