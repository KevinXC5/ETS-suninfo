package com.sxis.service;

import java.util.HashMap;
import java.util.List;

import org.apache.log4j.Logger;

import com.sxis.biz.access.dao.IInterfaceDAO;
import com.sxis.biz.access.dao.impl.InterfaceDAOImpl;
import com.sxis.biz.access.manage.IInterfaceBiz;
import com.sxis.biz.access.manage.impl.InterfaceBizImpl;
import com.sxis.biz.access.po.Interface;
import com.sxis.biz.access.util.InterfaceConstants;
import com.sxis.biz.util.ConfFileUtil;

public class InterfaceService {
	public static Logger logger = Logger.getLogger(InterfaceService.class);

	public static void main(String[] args) {
		IInterfaceBiz interfaceBiz = new InterfaceBizImpl();
		IInterfaceDAO interfaceDAO = new InterfaceDAOImpl();
		try {
			List<Interface> interfaces = interfaceBiz.getView();

			for (Interface face : interfaces) {
				HashMap<String, String> sysMap = interfaceDAO
						.getManageInterface(InterfaceConstants.File_NAME_TAG + face.getDevice());

				// 将网卡信息添加到sysMap对象中
				sysMap.remove(InterfaceConstants.IPADDR_KEY);
				sysMap.remove(InterfaceConstants.NETMASK_KEY);
				sysMap.remove(InterfaceConstants.GATEWAY_KEY);
				sysMap.remove(InterfaceConstants.DNS1_KEY);

				sysMap.put(InterfaceConstants.IPADDR_KEY, face.getIp());
				sysMap.put(InterfaceConstants.NETMASK_KEY, face.getMask());
				sysMap.put(InterfaceConstants.GATEWAY_KEY, face.getGateWay());
				sysMap.put(InterfaceConstants.DNS1_KEY, face.getDns());

				if ("stop".equalsIgnoreCase(args[0])) {// 关闭服务后
					sysMap.remove(InterfaceConstants.ONBOOT_KEY);
					sysMap.put(InterfaceConstants.ONBOOT_KEY,
							InterfaceConstants.NO);
				} else if ("start".equalsIgnoreCase(args[0])) {// 启动服务前
					sysMap.remove(InterfaceConstants.ONBOOT_KEY);
					sysMap.put(InterfaceConstants.ONBOOT_KEY,
							InterfaceConstants.DOWN.equalsIgnoreCase(face
									.getIfStatus()) ? InterfaceConstants.NO
									: InterfaceConstants.YES);

					if (InterfaceConstants.DHCP.equalsIgnoreCase(sysMap
							.get(InterfaceConstants.BOOTPROTO_KEY))) {//修改自动获取ip为设置静态ip方式
						sysMap.remove(InterfaceConstants.ONBOOT_KEY);
						sysMap.put(InterfaceConstants.BOOTPROTO_KEY,
								InterfaceConstants.NONE);
					}
				}

				if (sysMap != null) {
					// 修改系统网卡
					ConfFileUtil
							.writeToConffile(InterfaceConstants.File_NAME_TAG
									+ face.getDevice(), face.getDevice(),
									sysMap);
				}
			}

		} catch (Exception e) {
			logger.error("将ifence网卡添加到系统网卡出错");
		}
	}

}
