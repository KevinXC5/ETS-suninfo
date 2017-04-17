package com.sxis.service;

import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import org.apache.log4j.Logger;

import com.sxis.biz.baseinfo.paramconfig.manage.ISwMgmtInfoBiz;
import com.sxis.biz.baseinfo.paramconfig.manage.impl.SwMgmtInfoBizImpl;
import com.sxis.biz.baseinfo.paramconfig.po.SwMgmtInfo;
import com.sxis.biz.common.dao.HibernateSessionFactory;
import com.sxis.biz.switches.manage.ISnmpInfoBiz;
import com.sxis.biz.switches.manage.impl.SnmpInfoBizImpl;
import com.sxis.biz.util.ConfFileUtil;


public class SwitchScanEntryTask extends TimerTask {
	private static Logger logger = Logger.getLogger(SwitchScanEntryTask.class.getName());
	
	@Override
	public void run() {
		HibernateSessionFactory.getSession().beginTransaction();//开启事务
		
		ISwMgmtInfoBiz swMgmtInfoBiz = new SwMgmtInfoBizImpl();
		List<SwMgmtInfo> switchInfo = swMgmtInfoBiz.getSwitchName();
		String row = ConfFileUtil.SWITCH_SCAN_FLAG;
		logger.info("配置文件中获取到的交换机扫描标志为 " + row);
		if("no".equalsIgnoreCase(row)){
			if(switchInfo.size() == 0){
				ConfFileUtil.writeToIfence("sysclear", "switch_scan_flag", "no");
				logger.info("给交换机扫描的配置文件中赋值为no ,表示十五秒调用一次查询");
				ISnmpInfoBiz sib = new SnmpInfoBizImpl();
				sib.executeScan();
			}else{
				ConfFileUtil.writeToIfence("sysclear", "switch_scan_flag", "yes");
				logger.info("给交换机扫描的配置文件中赋值为yes ,开启十五分钟交换机查询");
				Timer timer1 = new Timer();
				timer1.schedule(new SwitchScanTask(), 0, 1000 * 60 * 15);
				if ("MVG".equalsIgnoreCase(ConfFileUtil.ACCESS_TECHNOLOGY)) {
					Timer timer2 = new Timer();
					timer2.schedule(new WirelessAPTask(), 0, 1000 * 60 * 15);
				}
				this.cancel();
			}
		}

		if(HibernateSessionFactory.getSession().isOpen() && HibernateSessionFactory.getSession().getTransaction() != null
				&& HibernateSessionFactory.getSession().getTransaction().isActive()){
			HibernateSessionFactory.getSession().getTransaction().commit();//提交事务
		}
		HibernateSessionFactory.closeSession();//关闭session
	}
	
	
}
