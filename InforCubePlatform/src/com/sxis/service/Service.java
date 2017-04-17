package com.sxis.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Timer;

import org.apache.log4j.Logger;

import com.sxis.biz.access.manage.IInterfaceBiz;
import com.sxis.biz.access.manage.impl.InterfaceBizImpl;
import com.sxis.biz.access.util.TimeUtil;
import com.sxis.biz.auditmanagement.util.AuditLogTimer;
import com.sxis.biz.auditmanagement.util.ReportTimer;
import com.sxis.biz.baseinfo.paramconfig.po.AuthenticateParam;
import com.sxis.biz.baseinfo.user.util.ADProcessTimer;
import com.sxis.biz.dhcp.manage.IDhcpBiz;
import com.sxis.biz.dhcp.manage.impl.DhcpBizImpl;
import com.sxis.biz.manage.util.ArpUtil;
import com.sxis.biz.sysconf.manage.ActivationMsg;
import com.sxis.biz.system.manage.IBackupconfigBiz;
import com.sxis.biz.system.manage.impl.BackupconfigBizImpl;
import com.sxis.biz.system.po.Backupconfig;
import com.sxis.biz.util.ConfFileUtil;
import com.sxis.biz.util.SystemConstants;
import com.sxis.captiveportal.util.BridgePortalStarter;
import com.sxis.captiveportal.util.CaptivePortalStarter;
import com.sxis.dhcp.DhcpProcess;
import com.sxis.dns.GetDnsConf;

public class Service {
	private static Logger logger = Logger.getLogger(Service.class.getName());

	/**
	 * 执行终端命令的函数
	 * 
	 * @param cmd
	 * @return
	 * @throws IOException
	 *             2013-2-25
	 */
	public static String cmdExe(String command) {
		BufferedReader br = null;
		InputStreamReader isr = null;
		String res = "";
		try {
			Process ps = Runtime.getRuntime().exec(command);
			isr = new InputStreamReader(ps.getInputStream());
			br = new BufferedReader(isr);
			String result = null;
			while (null != (result = br.readLine())) {
				res += result;
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			logger.error(command + "命令执行失败！ " + e.getMessage());
			return command + "命令执行失败！ ";

		} finally {
			try {
				if (null != isr) {
					isr.close();
				}
				if (null != br) {
					br.close();
				}
			} catch (IOException e) {
				logger.error("关闭文件流出现异常 " + e.getMessage());
				return command + "命令执行失败！ ";
			}

		}
		return res;
	}

	public static String startService(String cmd) throws Exception {
		String result = cmdExe(cmd).toString();
		return result;
	}

	/**
	 * 先生成配置文件，然后按相应的命令执行radiusd
	 * 
	 * @return 2013-2-25
	 */
	public static boolean startRadius() {
//		HashMap<String, String> map = new HashMap<String, String>();
//		String ip = ConfFileUtil.getFromIfence("ha", "vip");
//		if ("".equals(ip)) {
//			ip = ConfFileUtil.getFromIfence("interface eth0", "ip");
//		}
//		map.put("management_ip", ip);
//		ConfFileUtil.parseTemplate(map,
//				ConfFileUtil.INSTALL_DIR + "conf/radiusd/radiusd.conf",
//				ConfFileUtil.INSTALL_DIR + "raddb/radiusd.conf");

		// try {
		// result =
		// Service.startService("/usr/sbin/radiusd -d " + ConfFileUtil.INSTALL_DIR + "raddb");
		// } catch (Exception e) {
		// logger.error("radius服务启动失败 "+result);
		// e.printStackTrace();
		// return false;
		// }
		// logger.info("radius服务启动成功 "+result);
		return true;
	}


	public static boolean startDNS() {
		if (!"MVG".equalsIgnoreCase(ConfFileUtil.ACCESS_TECHNOLOGY)) {
			logger.info("当前的准入技术不是虚拟网关技术，不需要启动dns服务器");
			return false;
		} else {
			String result = "";
			GetDnsConf.getIsolationConf();
			GetDnsConf.getNamedConf();
			GetDnsConf.getRegistrationConf();

			try {
				result = Service
						.startService("/usr/sbin/named -c " + ConfFileUtil.INSTALL_DIR + "var/conf/named.conf");
			} catch (Exception e) {
				logger.error("named服务启动失败 " + result,e);
				return false;
			}
			logger.info("named服务启动成功 " + result);
			return true;
		}
	}

	/**
	 * 先生成配置文件，然后按相应的命令执行DHCP
	 * 
	 * @return 2013-2-25
	 */
	public static boolean startDHCP() {
		if (!"MVG".equals(ConfFileUtil.ACCESS_TECHNOLOGY)) {
			logger.info("当前的准入技术不是虚拟网关技术，不需要启动dhcp服务器");
			return false;
		} else {
			try {
				IDhcpBiz dhcp = new DhcpBizImpl();
				dhcp.manageInterface("start");
				dhcp.generateDhcpconf();
				// dhcp.manageDhcpService();
				DhcpProcess.dhcpListener();
			} catch (Exception e) {
				logger.error("DHCP启动失败" ,e);
				return false;
			}
			logger.info("DHCP启动成功");
			return true;
		}
	}

	public static void startLogCleaner() {
		// 每天执行一次清理进程，清理60天前的备份文件和180天前的log数据
		logger.info("启动log表清理进程！");
		Timer timer = new Timer();
		timer.schedule(new CleanTask(1), 0, 1000 * 60 * 60 * 24);
	}

	public static void startSwiInfoScaner() {
		// 每2分钟执行一次交换机信息扫面任务
		logger.info("启动交换机信息扫描进程！ ");
		Timer timer0 = new Timer();
		timer0.schedule(new SwitchScanEntryTask(), 0, 1000 * 60);
//		Timer timer1 = new Timer();
//		timer1.schedule(new SwitchScanTask(), 0, 1000 * 60 * 15);
//		if ("MVG".equalsIgnoreCase(ConfFileUtil.ACCESS_TECHNOLOGY)) {
//			Timer timer2 = new Timer();
//			timer2.schedule(new WirelessAPTask(), 0, 1000 * 60 * 2);
//		}
	}
	
	/**
	 * 定时执行系统自动备份功能
	 * @throws Exception
	 */
	@SuppressWarnings("static-access")
	public static void startBackup() throws Exception{
		logger.info("启动备份文件的定时备份！ ");
		IBackupconfigBiz backupconfigBiz = new BackupconfigBizImpl();
		
		//获取系统自动备份的相关信息，以下相邻的是备份间隔的获取
		Backupconfig info = backupconfigBiz.getInfoById(1);
		String backupPeriod = info.getBackupperiod();
		String backupPeriodUnit = info.getBackupperiodunit();
		long scheduleTime = 0;
		if("D".equals(backupPeriodUnit)){
			scheduleTime = Integer.valueOf(backupPeriod);
		}else if("W".equals(backupPeriodUnit)){
			scheduleTime = 7*Integer.valueOf(backupPeriod);
		}else if("M".equals(backupPeriodUnit)){
			scheduleTime = 30*Integer.valueOf(backupPeriod);
		}
		
		//获取系统备份的具体时刻
		String backupTime = info.getBackuptime();
		String backupTimeMin = info.getBackuptimemin();
		
		SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
		Date date = new Date();// 取时间
		
		//获取自动生成日志的excel文件时间，数据库默认为每天的23点59分
		Backupconfig auditLog = backupconfigBiz.getInfoById(2);
		String auditLogTime = formatter.format(date) + " " + auditLog.getBackuptime() + ":" + auditLog.getBackuptimemin() + ":00";
		
		//系统备份的事件处理，当前时间超过系统执行备份的时刻，推迟一天执行
		String dateTime = formatter.format(date) + " " + backupTime + ":" + backupTimeMin + ":00";
		if(Timestamp.valueOf(dateTime).before(new Date())){
			Calendar calendar = new GregorianCalendar();
			calendar.setTime(date);
			calendar.add(calendar.DATE, 1);// 把日期往后增加一天.整数往后推,负数往前移动
			date = calendar.getTime(); // 这个时间就是日期往后推一天的结果
			dateTime = formatter.format(date) + " " + backupTime + ":" + backupTimeMin + ":00";
		}
		
		//执行定时器
		Timer timer = new Timer();
		formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		timer.schedule(new BackupTask(), formatter.parse(dateTime), 1000 * 60 * 60 * 24 * scheduleTime);
		timer.schedule(new AuditLogTimer(), formatter.parse(auditLogTime), 1000 * 60 * 60 * 24);
	}

	@SuppressWarnings("static-access")
	public static void startTimer() throws Exception {

		logger.info("启动定时器将在线终端切换切换到注册vlan！");
		if ("PBR".equalsIgnoreCase(ConfFileUtil.ACCESS_TECHNOLOGY)) {// 策略路由
			SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
			Date date = new Date();// 取时间
			String reportTime = formatter.format(date) + " 23:59:00";
			
			Calendar calendar = new GregorianCalendar();
			calendar.setTime(date);
			calendar.add(calendar.DATE, 1);// 把日期往后增加一天.整数往后推,负数往前移动
			date = calendar.getTime(); // 这个时间就是日期往后推一天的结果
			
//			String dateString = formatter.format(date) + " 02:00:00";

			Timer timer = new Timer();
			formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			//定时器添加报表所需数据
			timer.schedule(new ReportTimer(), formatter
					.parse(reportTime), 1000 * 60 * 60 * 24);
			//定时器进行arp同步
			//timer.scheduleAtFixedRate(new ArpTimer(), formatter.parse(dateString), 1000 * 60 * 60 * 24);
			
			
			//AD域同步
//			adProcess(timer);
			
//			String source = ConfFileUtil.DATA_DIR + "addons/NACClient_Setup";
//			ZipUtils.createZip(source, source + ".zip");
			String mode = ConfFileUtil.getFromIfence("access", "technology_mode");
			if(SystemConstants.PBR.equalsIgnoreCase(mode)){
				// 启动策略路由采集平台
				CaptivePortalStarter.start();
			} else {
				BridgePortalStarter.start();
			}
			
			Thread.sleep(2000);
			ArpUtil.arpProcess();
			
			
		} else {// 虚拟网关
			// 定时将在线设备切换到注册vlan
//			INodeBiz deviceBiz = new NodeBizImpl();
//			List<Node> nodes = deviceBiz.getAllRegDevice();
//			
//			for (Node node : nodes) {
//				Locationlog ll = new Locationlog();
//				ll.setPort(node.getLastPort());
//				ll.setSw(node.getLastSwitch());
//				ll.setVlan(ConfFileUtil.REGISTRATION_VLAN);
//				ll.setMac(node.getMac());
//				TimerUtil.run(node.getUnregdate(), node);
//			}
//			
//			logger.info("启动trap接收进程！");
//			MultiThreadTrapReceiver.startTrapReceiver();
		}

	}
	
	public static void startActivation() throws Exception {
		Timer timer3 = new Timer();
		timer3.schedule(new ActivationMsg(), 0, 1000 * 60 * 10);
	}
	
	
	/**
	 * AD域同步
	 * @param timer
	 */
	public static void adProcess(Timer timer){
		AuthenticateParam authenticateParam = new AuthenticateParam();
		List<String> server_AuthTypes = authenticateParam.getServerAuthType();
		boolean existsADReg = false;
		if (server_AuthTypes.size() > 1) {
			for (String authType : server_AuthTypes) {
				if(authType !=null && "AD".equalsIgnoreCase(authType)){
					existsADReg = true;
					break;
				}	
			}
		}
		
		if(existsADReg){
			//AD域同步
			String adHost = ConfFileUtil.getFromIfence("ad", "server");
			String adProcessPeriodStr = ConfFileUtil.getFromIfence("ad", "processPeriod");
			String user_base = ConfFileUtil.getFromIfence("ad", "user_base");
			String username =  ConfFileUtil.getFromIfence("ad", "username");
			if(null != adHost && !"".equalsIgnoreCase(adHost) && adProcessPeriodStr.length() > 1 
					&& null != user_base && !"".equalsIgnoreCase(user_base) 
					&& null != username && !"".equalsIgnoreCase(username)){
				int adProcessPeriod = Integer.parseInt(adProcessPeriodStr.substring(0, adProcessPeriodStr.length()-1));
				String adProcessPeriodUnit = adProcessPeriodStr.substring(adProcessPeriodStr.length()-1);
				
				timer.schedule(new ADProcessTimer(), new Date(),  TimeUtil.getMillisecondByUnit(adProcessPeriodUnit) * adProcessPeriod);
				
			}
		}
		
	}

	public static void main(String[] args) throws Exception {

		// 初始化网卡信息
		IInterfaceBiz interfaceBiz = new InterfaceBizImpl();
		logger.info("初始化网卡信息！");
		interfaceBiz.initInterfaces();
		
		//进行系统出厂备份
/*		ISystemBiz systemBiz = new SystemBizImpl();
		systemBiz.factoryBackup();*/
		
		// 初始化双机配置
		Service.startActivation();
		Service.startDNS();
		Service.startDHCP();
		Service.startRadius();
		Service.startLogCleaner();
//		Service.startSwiInfoScaner();
		Service.startBackup();
		Service.startTimer();
		
	}
}
