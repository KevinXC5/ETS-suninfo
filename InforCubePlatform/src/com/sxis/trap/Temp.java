package com.sxis.trap;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;

public class Temp implements CommandResponder {
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
	private MessageProcessSend messageProcessSend = MessageProcessSend.getInstance();
	
	/**
	 * 获取该Trap监听端口使用的线程池
	 * @return 线程池对象, 可使用该对象来停止该Trap监听端口的Trap接收服务
	 */
	public ThreadPool getThreadPool() {
		return threadPool;
	}
	
	public Temp(String ip, int port, List<String> communitys) {
		listenAddress = GenericAddress.parse(System.getProperty("snmp4j.listenAddress", "udp:" + "0.0.0.0" + "/" + port));
		if (communitys != null) {
			this.communitys = communitys;
		}
	}
	
	/**
	 * 开始Trap的接收监听
	 * 
	 * @throws Exception init()方法抛出
	 */
	public void run() throws Exception {
		init();
		snmp.addCommandResponder(this);
	}

	private void init() throws IOException {
		threadPool = ThreadPool.create("Trap " + listenAddress, 2);
		dispatcher = new MultiThreadedMessageDispatcher(threadPool,
				new MessageDispatcherImpl());

		// 对TCP与UDP协议进行处理
		if (listenAddress instanceof UdpAddress) {
			transport = new DefaultUdpTransportMapping((UdpAddress) listenAddress);
		} else {
			transport = new DefaultTcpTransportMapping((TcpAddress) listenAddress);
		}
		snmp = new Snmp(dispatcher, transport);
		snmp.getMessageDispatcher().addMessageProcessingModel(new MPv1());
		snmp.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
		snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3());
		USM usm = new USM(SecurityProtocols.getInstance(), 
				new OctetString(MPv3.createLocalEngineID()), 0);
		SecurityModels.getInstance().addSecurityModel(usm);
		snmp.listen();
	}
	
	/**
	 * 实现CommandResponder的processPdu方法, 用于处理传入的请求、PDU等信息 当接收到trap时，会自动进入这个方法
	 * 
	 * @param respEvnt
	 */
	@Override
	public void processPdu(CommandResponderEvent event) {
//		System.out.println("xjd");
//		String community = new String(event.getSecurityName());
//		if (communitys.contains(community)) {
//			messageProcessSend.submitTrapEvent(event);
//			// log
//		}else{
//			// log
//		}
//		if (event != null && event.getPDU() != null) {
//			Vector<VariableBinding> recVBs = event.getPDU().getVariableBindings();
//			for (int i = 0; i < recVBs.size(); i++) {
//				VariableBinding recVB = recVBs.elementAt(i);
//				System.out.println(recVB.getOid() + " : " + recVB.getVariable());
//			}
//		}

	}
	
//	public static void main(String[] args) {
//		List<String> community = new ArrayList<String>();
//		community.add("public");
//		community.add("private");
//		Temp mtr = new Temp("127.0.0.1", 162, community);
//		try {
//			mtr.run();
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
//	}

}
