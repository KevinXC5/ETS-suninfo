package com.sxis.captiveportal.util;

import java.io.IOException;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Set;
import java.util.prefs.BackingStoreException;

import org.apache.log4j.Logger;
import org.krakenapps.pcap.live.PcapDeviceManager;
import org.krakenapps.pcap.live.PcapDeviceMetadata;

import com.sxis.biz.access.manage.IInterfaceBiz;
import com.sxis.biz.access.manage.impl.InterfaceBizImpl;
import com.sxis.biz.access.po.Interface;
import com.sxis.biz.access.util.InterfaceConstants;
import com.sxis.biz.util.ConfFileUtil;
import com.sxis.captiveportal.discoveryservice.impl.CaptivePortalService;
import com.sxis.service.Service;

/**
 * 透明网桥采集平台启动管理类
 * @author KevinXC
 * @date 2014-10-30
 */
public class BridgePortalStarter {
	private final static Logger logger = Logger.getLogger(BridgePortalStarter.class.getName());
	private static IInterfaceBiz interfaceBiz = new InterfaceBizImpl();

	/**
	 * 透明网桥模式 采集平台启动方法
	 * @throws Exception
	 */
	public static void start() throws Exception {
		//获取所有网桥
		HashMap<String, HashMap<String, Interface>> bridgeMap = interfaceBiz.getUpBridges();
		Set<String> bridgeNames = bridgeMap.keySet();
	
		String deviceName = null;
		PcapDeviceMetadata selectedmetadata = null;
		//  迭代网卡，将网桥设备中连接下行的网卡进行报文监听
		for (PcapDeviceMetadata metadata : PcapDeviceManager.getDeviceMetadataList()) {
			for (String bridgeName : bridgeNames) {
				HashMap<String, Interface>  bridge =  bridgeMap.get(bridgeName);
				Interface mgntIfc =  bridge.get(InterfaceConstants.ENFORCEMENT_MANAGEMENT);
				Interface downLinkIfc = bridge.get(InterfaceConstants.DOWN);
				if(mgntIfc != null && metadata.getName().equalsIgnoreCase(downLinkIfc.getDevice())){//只对网桥中的下行网卡进行监听
					deviceName = metadata.getName();
					selectedmetadata = metadata;
					
					CaptivePortalService cpService = new CaptivePortalService();
					try {
						cpService.setGatewayAddress(InetAddress.getByName(mgntIfc.getGateWay()));
						
						cpService.setRedirectAddress(InetAddress.getByName(mgntIfc.getIp()));
						logger.info("redirectIP 指向物理ip " + mgntIfc.getIp());
						cpService.setArpInterval(ConfFileUtil.ARP_POLLINGINTERVAL);
						cpService.setPcapDeviceName(deviceName);
						
						cpService.start();
					} catch (BackingStoreException e) {
						e.printStackTrace();
					} catch (IOException e) {
						e.printStackTrace();
					}
					
					logger.info("选择的网卡为：" + selectedmetadata.getName() + " , "
							+ selectedmetadata.getDescription() + " , "
							+ selectedmetadata.getMacAddress());
					break;
				}else if(metadata.getName().equalsIgnoreCase(downLinkIfc.getDevice())){
					logger.info("网桥 "+ bridgeName + "未指定管理网卡");
					break;
				}
			}
		}

		if (deviceName == null || selectedmetadata == null) {
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
