package com.sxis.captiveportal.util;

import java.io.IOException;
import java.net.InetAddress;
import java.util.List;
import java.util.prefs.BackingStoreException;

import org.apache.log4j.Logger;
import org.krakenapps.pcap.live.PcapDeviceManager;
import org.krakenapps.pcap.live.PcapDeviceMetadata;

import com.sxis.biz.access.manage.IInterfaceBiz;
import com.sxis.biz.access.manage.impl.InterfaceBizImpl;
import com.sxis.biz.access.po.Interface;
import com.sxis.biz.util.ConfFileUtil;
import com.sxis.captiveportal.discoveryservice.impl.CaptivePortalService;
import com.sxis.service.Service;

/**
 * PBR模式采集平台启动管理类
 * @author KevinXC
 * @date 2013-6-25
 */
public class CaptivePortalStarter {
	private final static Logger logger = Logger.getLogger(CaptivePortalStarter.class.getName());
	private static IInterfaceBiz interfaceBiz = new InterfaceBizImpl();
	
	/**
	 * PBR 采集平台启动函数
	 * @throws Exception 
	 */
	public static void start() throws Exception {
		List<Interface> list = interfaceBiz.getAllUpInterfaces();
		for (Interface face : list) {
			// ip配置出错，无法启动采集平台
			if ("".equals(face.getNext_hop()) || null == face.getNext_hop() 
					|| "".equals(face.getIp()) || null == face.getIp()) {
				logger.error("网卡 ifIndex - " + face.getIfIndex() 
						+ " ,device - " + face.getDevice() 
						+ "ip配置出错，无法启动采集平台! nextHop - " + face.getNext_hop() 
						+ " 系统网卡 - " + face.getIp());
//				stopIfence();
				return;
			}
		}
		
		String deviceName = null;
		PcapDeviceMetadata selectedmetadata = null;
		for (PcapDeviceMetadata metadata : PcapDeviceManager.getDeviceMetadataList()) {
			System.out.println(metadata.getName()+" , " + metadata.getDescription() + " , " + metadata.getMacAddress());
			for (Interface face : list) {
				if (face.getDevice().equalsIgnoreCase(metadata.getName().trim())) {
					deviceName = metadata.getName();
					selectedmetadata = metadata;
					
					CaptivePortalService cpService = new CaptivePortalService();
					String haSwitch = ConfFileUtil.getFromIfence("ha", "haswitch");
					
					try {
						cpService.setGatewayAddress(InetAddress.getByName(face.getNext_hop()));
						
						if ("off".equals(haSwitch)) {
							cpService.setRedirectAddress(InetAddress.getByName(face.getIp()));
							logger.info("未开启双机，redirectIP 指向物理ip " + face.getIp());
						} else {
							String index = face.getDevice().replaceAll("eth", "");
							String vip = ConfFileUtil.getFromIfence("ha", "vip" + index);
							cpService.setRedirectAddress(InetAddress.getByName(vip));
							logger.info("开启了双机，redirectIP 指向虚拟ip " + vip);
						}
						cpService.setArpInterval(ConfFileUtil.ARP_POLLINGINTERVAL);
						cpService.setPcapDeviceName(deviceName);
						
						cpService.start();
					} catch (BackingStoreException e) {
						e.printStackTrace();
					} catch (IOException e) {
						e.printStackTrace();
					}
					
					logger.info("选择的网卡为："+selectedmetadata.getName()+" , " 
							+ selectedmetadata.getDescription() + " , " 
							+ selectedmetadata.getMacAddress());
					break;
				}
			}
		}
		
		if(deviceName == null || selectedmetadata == null){
			logger.error("没有可选择的网卡");
		}
	}
	
	/**
	 * 调用perl脚本停止service.jar
	 */
	public static void stopIfence() {
		Service.cmdExe("perl " + ConfFileUtil.INSTALL_DIR + "stopJAR.pl");
		logger.info("停止ifence进程");
	}
}
