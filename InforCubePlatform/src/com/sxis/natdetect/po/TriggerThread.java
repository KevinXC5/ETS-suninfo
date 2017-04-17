package com.sxis.natdetect.po;

import java.sql.SQLException;

import org.apache.log4j.Logger;

import com.sxis.biz.authenticate.manage.impl.AuthenticateBiz;
import com.sxis.biz.baseinfo.iplog.manage.IIpLogBiz;
import com.sxis.biz.baseinfo.iplog.manage.impl.IpLogBizImpl;
import com.sxis.biz.baseinfo.iplog.po.Iplog;
import com.sxis.biz.baseinfo.violation.manage.IViolationBiz;
import com.sxis.biz.baseinfo.violation.manage.impl.ViolationBizImpl;

/**
 * 触发非法NAT违规的线程类
 * @author KevinXC
 * @date 2014-3-27
 */
public class TriggerThread implements Runnable {
	private final static Logger logger = Logger.getLogger(TriggerThread.class.getName());
	private IlicitNAT nat;
	
	/**
	 * 默认构造函数 
	 */
	public TriggerThread() {
		super();
	}

	/**
	 * 带参构造函数
	 * @param nat
	 */
	public TriggerThread(IlicitNAT nat) {
		super();
		this.nat = nat;
	}

	public IlicitNAT getNat() {
		return nat;
	}

	public void setNat(IlicitNAT nat) {
		this.nat = nat;
	}

	@Override
	public void run() {
		try {
			//根据ip获取到非法NAT设备的mac地址
			String ip = this.nat.getIp();
			String mac = ipToMac(ip);
			
			//未找到mac地址，返回
			if (mac == null) {
				//将标志位置回false，便于下次添加违规
				this.nat.setNAT(false);
				return;
			}
			
			//触发违规
			int retVal = TriggerViolation(ip, mac);
			
			//表示没有开启路由违规，需要将flag至为false
			if (retVal == 0) {
				this.nat.setNAT(false);
			}
		} catch (Exception e) {
			logger.error("触发NAT违规时出现异常 " + e.getMessage());
		}
	}
	
	/**
	 * 通过biz层获取ip对应的mac地址
	 * @param ip
	 * @return
	 * @throws SQLException 
	 */
	public String ipToMac(String ip) throws SQLException {
		IIpLogBiz ipLogBiz = new IpLogBizImpl();
		Iplog ipLog = ipLogBiz.ip2Mac(ip);
		
		if (ipLog == null) {
			logger.info(ip + " 当前还没有对应的mac地址，此次无法触发违规");
			return null;
		}

		logger.info(ip + " 对应 mac 地址为 " + ipLog.getId().getMac());
		return ipLog.getId().getMac();
	}
	
	/**
	 * 调用biz层方法将相应mac添加到非法路由器违规
	 * @param mac
	 * @throws Exception 
	 * @throws SQLException 
	 */
	public int TriggerViolation(String ip, String mac) throws SQLException, Exception {
		logger.info("将 " + mac + " 添加一条NAT违规");
		
		//先判断此mac地址是否存在node表，不存在则要添加
		AuthenticateBiz authentivateBiz = new AuthenticateBiz();
//		authentivateBiz.dnRequestByNode(ip,mac);
		authentivateBiz.isDetected(ip, null);
		
		IViolationBiz violationBiz = new ViolationBizImpl();
		
		//先查看是否已经存在一条此mac对应的NAT违规，如果有则不进行添加
		int count = violationBiz.getViolationClassByMac(mac, "1100008");
		if (count != 0) {
			logger.info("系统里已经存在一条 " + mac + " 的NAT违规，不做操作");
			return 1;
		}
		
		//mac对应的若为win设备，则不作操作
//		INodeBiz nodeBiz = new NodeBizImpl();
//		Node node = nodeBiz.getNodeByMAC(mac);
//		String os = node.getDhcpFingerprint();
//		if (os != null && !os.startsWith("Linux") && !os.startsWith("unknown")) {
//			logger.info(mac + " 对应的终端为 " + os +" 设备，不应添加NAT违规，返回");
//			return 1;
//		}
		
		//添加一条open的违规
		return violationBiz.addViolationRouter(mac);
	}
	
}
