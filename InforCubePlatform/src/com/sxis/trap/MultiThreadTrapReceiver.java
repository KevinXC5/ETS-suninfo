package com.sxis.trap;

import java.io.IOException;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TcpAddress;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;

import com.sxis.biz.access.dao.IVlanDAO;
import com.sxis.biz.access.dao.impl.VlanDAOImpl;
import com.sxis.biz.access.manage.IVlanBiz;
import com.sxis.biz.access.manage.impl.VlanBizImpl;
import com.sxis.biz.access.util.SnmpUtils;
import com.sxis.biz.access.util.TimerUtil;
import com.sxis.biz.baseinfo.devicemanage.manage.IIpmacRealtimeBiz;
import com.sxis.biz.baseinfo.devicemanage.manage.INodeBiz;
import com.sxis.biz.baseinfo.devicemanage.manage.impl.IpmacRealtimeBizImpl;
import com.sxis.biz.baseinfo.devicemanage.manage.impl.NodeBizImpl;
import com.sxis.biz.baseinfo.devicemanage.po.IpmacRealtime;
import com.sxis.biz.baseinfo.devicemanage.po.Node;
import com.sxis.biz.switches.manage.SwitchFactory;
import com.sxis.biz.switches.manage.impl.SwitchFactoryImpl;
import com.sxis.biz.switches.po.Switch;
import com.sxis.biz.util.ConfFileUtil;

public class MultiThreadTrapReceiver implements CommandResponder {

	private INodeBiz deviceBiz = new NodeBizImpl();
	public Logger logger = Logger.getLogger(MultiThreadTrapReceiver.class
			.getName());

	/**
	 * 信息分发. 用来分配接收Trap信息的线程.
	 */
	private MultiThreadedMessageDispatcher dispatcher;

	/**
	 * snmp对象，用来处理Trap信息的接收
	 */
	private Snmp snmp = null;

	/**
	 * 监听设备对象，包含监听的地址和端口
	 */
	private Address listenAddress;

	/**
	 * 该端口只接收的该属性列表中的包含的共同体名的Trap信息
	 */
	@SuppressWarnings("unused")
	private List<String> communitys = new ArrayList<String>();

	/**
	 * 用来接收Trap消息的线程池
	 */
	private ThreadPool threadPool;

	/**
	 * snmp网络连接, 用来提供关闭连接服务.
	 */
	private TransportMapping transport;

	/**
	 * 数据处理. 接收到的Trap事件交由该对象处理.
	 */
	@SuppressWarnings("unused")
	private MessageProcessSend messageProcessSend = MessageProcessSend
			.getInstance();

	/**
	 * 获取该Trap监听端口使用的线程池
	 * 
	 * @return 线程池对象, 可使用该对象来停止该Trap监听端口的Trap接收服务
	 */
	public ThreadPool getThreadPool() {
		return threadPool;
	}

	public MultiThreadTrapReceiver(String ip, int port, List<String> communitys) {
		listenAddress = GenericAddress.parse(System.getProperty(
				"snmp4j.listenAddress", "udp:" + "0.0.0.0" + "/" + port)); // 本地IP与监听端口
		if (communitys != null) {
			this.communitys = communitys;
		}
	}

	/**
	 * 开始Trap的接收监听
	 * 
	 * @throws Exception
	 *             init()方法抛出
	 */
	public void run() throws Exception {
		init();
		snmp.addCommandResponder(this);
		System.out.println("开始监听Trap信息!");
		logger.info("---开始监听Trap信息!");
	}

	private void init() throws UnknownHostException, IOException {
		threadPool = ThreadPool.create("Trap" + listenAddress, 2);
		dispatcher = new MultiThreadedMessageDispatcher(threadPool,
				new MessageDispatcherImpl());

		// 对TCP与UDP协议进行处理
		if (listenAddress instanceof UdpAddress) {
			transport = new DefaultUdpTransportMapping(
					(UdpAddress) listenAddress);
		} else {
			transport = new DefaultTcpTransportMapping(
					(TcpAddress) listenAddress);
		}
		snmp = new Snmp(dispatcher, transport);
		snmp.getMessageDispatcher().addMessageProcessingModel(new MPv1());
		snmp.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
		snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3());
		USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3
				.createLocalEngineID()), 0);
		SecurityModels.getInstance().addSecurityModel(usm);
		snmp.listen();
	}

	/**
	 * 实现CommandResponder的processPdu方法, 用于处理传入的请求、PDU等信息 当接收到trap时，会自动进入这个方法
	 * 
	 * @param respEvnt
	 */
	@SuppressWarnings("unchecked")
	@Override
	public void processPdu(CommandResponderEvent respEvnt) {
		logger.info("---接受并开始处理trap报文");
		SimpleDateFormat dateFmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		String trap_type = "";
		String sw_address = "";
		String sw_ip = "";
		String if_index = "";
		String if_desc = "";
		String if_vlan = "";
		String if_mac = "";
		String down_type = "";
		String sw_sysinfo = "";
		// System.out.println(respEvnt.getPeerAddress().toString());

		SwitchFactory sf = new SwitchFactoryImpl();
		Switch sw = null;

		// 解析Response
		if (respEvnt != null && respEvnt.getPDU() != null) {
			Vector<VariableBinding> recVBs = (Vector<VariableBinding>) respEvnt
					.getPDU().getVariableBindings();

//			Locationlog locationlog = new Locationlog();
			sw_address = respEvnt.getPeerAddress().toString();
			sw_ip = sw_address.substring(0, sw_address.indexOf("/"));
			sw = sf.getInstance(sw_ip);

			// 判断2960交换机，系统信息OID不同
			String sw_sysinfoOid = sw.getOids().get("switchInfoValue");

			// 获取交换机SNMP版本信息
			String snmpVersion = sw.getSnmpVersion();
//			locationlog.setSw(sw_ip);

			String ifIndexOid = sw.getOids().get("ifIndex").endsWith(".") ? sw
					.getOids().get("ifIndex") : sw.getOids().get("ifIndex")
					+ ".";
			String ifDescrOid = sw.getOids().get("ifDescr").endsWith(".") ? sw
					.getOids().get("ifDescr") : sw.getOids().get("ifDescr")
					+ ".";
			String ifMacOid = sw.getOids().get("cpsIfSecureLastMacAddress")
					.endsWith(".") ? sw.getOids().get(
					"cpsIfSecureLastMacAddress") : sw.getOids().get(
					"cpsIfSecureLastMacAddress")
					+ ".";
			String locIfReasonOid = sw.getOids().get("locIfReason").endsWith(
					".") ? sw.getOids().get("locIfReason") : sw.getOids().get(
					"locIfReason");
			for (int i = 0; i < recVBs.size(); i++) {
				VariableBinding recVB = recVBs.elementAt(i);
				// System.out.println(recVB.getOid().toString() + ": " +
				// recVB.getVariable().toString());
				if (recVB.getOid().toString().contains(ifIndexOid)) {
					if_index = recVB.getVariable().toString();
				} else if (recVB.getOid().toString().contains(
						sw.getOids().get("snmpTrapOID"))) {
					trap_type = recVB.getVariable().toString();
				} else if (recVB.getOid().toString().contains(ifDescrOid)) {
					if_desc = recVB.getVariable().toString();
				} else if (recVB.getOid().toString().contains(locIfReasonOid)) {
					down_type = recVB.getVariable().toString();
				} else if (recVB.getOid().toString().contains(ifMacOid)) {
					if_mac = recVB.getVariable().toString();
				}
			}

//			locationlog.setConnection_type("SNMP-Traps");
//			locationlog.setPort(if_index);
//			locationlog.setPort_desc(if_desc);

			String sysInfoOid = sw.getOids().get("sysObjectID");
			// 区分为V1或者V2、3
			if ("1".equals(snmpVersion)) {
				if (if_mac == null || "".equals(if_mac)) {
					if_mac = SnmpUtils.getSimpleValueByV1(ifMacOid
							+ if_index, sw_ip, sw.getSnmpCommunityRead(), "161", 2000, 10);
				}
				sw_sysinfo = SnmpUtils.getSimpleValueByV1(sysInfoOid,
						sw_ip, sw.getSnmpCommunityRead(), "161",
						2000, 10);
			} else {
				if (if_mac == null || "".equals(if_mac)) {
					if_mac = SnmpUtils.getSimpleValueByV2(ifMacOid
							+ if_index, sw_ip, sw
							.getSnmpCommunityRead(), "161", 2000, 10);
				}
				sw_sysinfo = SnmpUtils.getSimpleValueByV2(sysInfoOid,
						sw_ip, sw.getSnmpCommunityRead(), "161",
						2000, 10);
			}

			logger.info("---获取终端mac地址：" + if_mac);
//			locationlog.setMac(if_mac);

			// 判断trap类型，进行上下网流程
			logger.info("trap_type:" + trap_type);
			String portSecurityStatusOid = sw.getOids().get(
					"cpsIfPortSecurityEnable").endsWith(".") ? sw.getOids()
					.get("cpsIfPortSecurityEnable") : sw.getOids().get(
					"cpsIfPortSecurityEnable")
					+ ".";
			if (trap_type.equals(sw.getOids().get("upPortSecurity"))) {
				IVlanBiz iVlan = new VlanBizImpl();
				try {
					if_vlan = iVlan.getActVlanByMac(if_mac);
					System.out.println(if_vlan);
				} catch (Exception e) {
					e.printStackTrace();
				}
				if (if_vlan == null || if_vlan.equals("")) {
					if_vlan = ConfFileUtil.REGISTRATION_VLAN;
				}
//				locationlog.setVlan(if_vlan);

				// 获取start_time
				String start_time = dateFmt.format(Calendar.getInstance()
						.getTime());
//				locationlog.setStarttime(start_time);

				IVlanDAO vd = new VlanDAOImpl();
				// 更新所有endtime为空的locationlog记录
				vd.updateAllLocationlog(start_time, if_mac);
				// 插入新locationlog
//				vd.addLocationlog(locationlog);
				// 接口绑定终端mac
				// String result =
				// SnmpUtils.setOidValue(SnmpConstants.CISCO_IF_MAC + if_index,
				// sw_ip, sw.getSnmpCommunityWrite(), "161", 2000, 2, if_mac,
				// org.snmp4j.mp.SnmpConstants.version2c, SnmpUtils.OCTSTRING);

				// 区分为V1或者V2、3
				if ("1".equals(snmpVersion)) {
					SnmpUtils.setOidValueByV1(portSecurityStatusOid + if_index,
							sw_ip, sw.getSnmpCommunityWrite(), "161", 2000, 1,
							Switch.PORTSECURITY_CLOSE, SnmpUtils.INTEGER32);
				} else {
					SnmpUtils.setOidValueByV2(portSecurityStatusOid + if_index,
							sw_ip, sw.getSnmpCommunityWrite(), "161", 2000, 1,
							Switch.PORTSECURITY_CLOSE, SnmpUtils.INTEGER32);
				}
				// 跳转vlan
				setVlan(Integer.parseInt(if_index), sw_ip, if_vlan);
				logger.info("---处理vlan跳转到： vlan-" + if_vlan);

				try {
					if (!if_vlan.equals(ConfFileUtil.REGISTRATION_VLAN)
							&& !if_vlan.equals(ConfFileUtil.ISOLATION_VLAN)
							&& !if_vlan.equals(ConfFileUtil.SCAN_VLAN)) {
						Node node = null;
						try {
							node = deviceBiz.getNodeByMAC(if_mac);
						} catch (Exception e) {
							e.printStackTrace();
						}
//						locationlog.setVlan(ConfFileUtil.REGISTRATION_VLAN);
//						TimerUtil.run(node.getUnregdate(), node);
						logger.info("---启动定时器");
					}
				} catch (NumberFormatException e) {
					e.printStackTrace();
				} catch (NullPointerException e) {
					e.printStackTrace();
				}

			} else if (trap_type.equals(sw.getOids().get("linkDown"))) {
				String trunkOid = sw.getOids().get("vlanTrunkPortDynamicState")
						.endsWith(".") ? sw.getOids().get(
						"vlanTrunkPortDynamicState") : sw.getOids().get(
						"vlanTrunkPortDynamicState")
						+ ".";
				String trunkPortState = SnmpUtils.getSimpleValueByV2(trunkOid
						+ if_index, sw_ip, sw
						.getSnmpCommunityRead(), "161", 2000, 10);
				if ("1".equals(snmpVersion)) {
					trunkPortState = SnmpUtils.getSimpleValueByV1(trunkOid
							+ if_index, sw_ip, sw
							.getSnmpCommunityRead(), "161", 2000, 10);
				} else {
					trunkPortState = SnmpUtils.getSimpleValueByV2(trunkOid
							+ if_index, sw_ip, sw
							.getSnmpCommunityRead(), "161", 2000, 10);
				}
				logger.info("down_type:" + down_type);
				if (down_type.contains(Switch.LOCIFREASON_LOST)
						|| (sw_sysinfoOid.equals(sw_sysinfo) && down_type
								.contains("up"))) {
					// 如果端口为trunk口则不作处理
					if ("1".equals(trunkPortState)
							|| "on".equals(trunkPortState)) {

					} else {
						logger.info("11111111111111");
						// 1. 更新locationlog、iplog(xxm暂时不需要)表最新一条记录的endtime 2.
						// 还原交换机vlan配置到mac-detection
						String end_time = dateFmt.format(Calendar.getInstance()
								.getTime());
//						locationlog.setEnd_time(end_time);
						IVlanDAO vlanDao = new VlanDAOImpl();
//						vlanDao.updateLocationlog(locationlog);// update方法只更新end_time
						if ("1".equals(snmpVersion)) {
							SnmpUtils.setOidValueByV1(portSecurityStatusOid
									+ if_index, sw_ip, sw
									.getSnmpCommunityWrite(), "161", 2000, 1,
									Switch.PORTSECURITY_OPEN,
									SnmpUtils.INTEGER32);
						} else {
							SnmpUtils.setOidValueByV2(portSecurityStatusOid
									+ if_index, sw_ip, sw
									.getSnmpCommunityWrite(), "161", 2000, 1,
									Switch.PORTSECURITY_OPEN,
									SnmpUtils.INTEGER32);
						}
						// 跳转vlan
						setVlan(Integer.parseInt(if_index), sw_ip,
								ConfFileUtil.MACDETECTION_VLAN);
						logger.info("---处理vlan跳转到： vlan-" + if_vlan);

						// ------------编辑断网时间
//						IAuditGetBiz d = new IAuditGetBizImpl();
//						int i = d.editNetDevices(if_mac, end_time);
						INodeBiz iDeviceBiz = new NodeBizImpl();
						String deviceMac = null;
						try {
							// List<Node> listNode =
							// iDeviceBiz.getAllRegDevice();
							// for(i=0;i<listNode.size();i++){
							// if(listNode.get(i).getLastPort() ==
							// locationlog.getPort() &&
							// listNode.get(i).getLastSwitch() ==
							// locationlog.getSw()){
							// deviceMac = listNode.get(i).getMac();
							// break;
							// }
							// }
							// deviceMac =
							// iDeviceDAO.getMacByPortAndSwitchip(locationlog.getPort(),
							// locationlog.getSw());
							iDeviceBiz.updateNodeByMac(if_mac);
						} catch (Exception e1) {
							e1.printStackTrace();
						}
						IIpmacRealtimeBiz imacIpUserBiz = new IpmacRealtimeBizImpl();
						try {
							IpmacRealtime del = new IpmacRealtime();
							del.setMac(if_mac);
							int m = imacIpUserBiz.delIpmacRealtime(del);
						} catch (Exception e) {
							e.printStackTrace();
						}

						// 取消定时器
						Node node = null;
						try {
							node = deviceBiz.getNodeByMAC(if_mac);
						} catch (Exception e) {
							e.printStackTrace();
						}
						TimerUtil.removeTimer(node);
					}

				} else if (down_type.contains(Switch.LOCIFREASON_SHUTDOWN)) {
					logger.info("－－－切换状态至shutdown");
					// 手动关闭交换机端口adminstat，不做处理
				}

			}

		}
	}

	private void setVlan(int if_index, String sw_ip, String desVlan) {
		IVlanBiz vlanBiz = new VlanBizImpl();
		vlanBiz.setVlanIn(if_index, sw_ip, desVlan);
	}

	public static void startTrapReceiver() {
		List<String> comm = new ArrayList<String>();
		comm.add("public");
		comm.add("private");
		MultiThreadTrapReceiver multithreadedtrapreceiver = new MultiThreadTrapReceiver(
				"127.0.0.1", 162, comm);
		try {
			multithreadedtrapreceiver.run();
		} catch (Exception e) {
			e.printStackTrace();
		}

		// multithreadedtrapreceiver.setVlan(10, "172.18.4.34",
		// ConfFileUtil.MACDETECTION_VLAN);
	}

	public static void main(String[] a) {
		// String admin_stat =
		// SnmpUtils.getSimpleValueByV2(SnmpConstants.CISCO_IF_ADMINSTAT_OID +
		// "2", "172.18.4.35", "public", "161", 2000, 10);
		// System.out.println("===" + admin_stat);

		List<String> comm = new ArrayList<String>();
		comm.add("public");
		comm.add("private");
		MultiThreadTrapReceiver multithreadedtrapreceiver = new MultiThreadTrapReceiver(
				"127.0.0.1", 162, comm);
		try {
			multithreadedtrapreceiver.run();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
