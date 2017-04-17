package com.sxis.service;

import java.io.File;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.TimerTask;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;

import com.sxis.biz.access.util.TimeUtil;
import com.sxis.biz.common.dao.BaseDAO;
import com.sxis.biz.common.dao.HibernateSessionFactory;
import com.sxis.biz.system.manage.IBackupconfigBiz;
import com.sxis.biz.system.manage.IBackupinfoBiz;
import com.sxis.biz.system.manage.impl.BackupconfigBizImpl;
import com.sxis.biz.system.manage.impl.BackupinfoBizImpl;
import com.sxis.biz.system.po.Backupconfig;
import com.sxis.biz.system.po.Backupinfo;
import com.sxis.biz.util.ConfFileUtil;
import com.sxis.constants.SnmpConstants;

public class CleanTask extends TimerTask {
	private static Logger logger = Logger.getLogger(CleanTask.class.getName());
	private int flag;// 1为清理30D数据(备份文件、iplog表、locationlog表)，2为清理180D数据(adminaudit表、portalaudit表)
	private static final File dir = new File(ConfFileUtil.INSTALL_DIR + "tomcat/logs/");

	private SimpleDateFormat dateform;

	public CleanTask(int flag) {
		this.flag = flag;
	}

	@Override
	public void run() {
		Connection conn = null;

		if (flag == 1) {
			HibernateSessionFactory.getSession().beginTransaction();//开启事务
			// 1. 清理备份文件(60D)
			cleanBakupFile();

			// 清理tomcat日志文件(ND)
			cleanTomcatLogs();

			// 2. 清理表数据(60D)
			BaseDAO baseDao = new BaseDAO();
			dateform = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			Statement st = null;
			try {
				conn = baseDao.getConnection();

				//注释掉原来的写法
//				Calendar presDate = Calendar.getInstance();
//				presDate.add(Calendar.DAY_OF_MONTH, -180);
//				String presDateStr = dateform.format(presDate.getTime());
				
				IBackupconfigBiz backupconfigBiz = new BackupconfigBizImpl();
				Backupconfig auditLog = backupconfigBiz.getInfoById(2);
				Date date = new Date();
				String presDateStr = "";
				if("D".equalsIgnoreCase(auditLog.getKeeptimeunit())){
					presDateStr = TimeUtil.timeAdd(date, Calendar.DATE, -Integer.valueOf(auditLog.getKeeptime()));
				}else if("M".equalsIgnoreCase(auditLog.getKeeptimeunit())){
					presDateStr = TimeUtil.timeAdd(date, Calendar.MONTH, -Integer.valueOf(auditLog.getKeeptime()));
				}else if("Y".equalsIgnoreCase(auditLog.getKeeptimeunit())){
					presDateStr = TimeUtil.timeAdd(date, Calendar.YEAR, -Integer.valueOf(auditLog.getKeeptime()));
				}
				
				st = conn.createStatement();
				String []sqls = {
						"delete from portalaudit where portaltime<'"+ presDateStr + "'",
						"delete from regdevices where start_time<'"+ presDateStr + "'",
						"delete from adminaudit where usertime<'" + presDateStr + "'",
						"delete from violationaudit where starttime<'" + presDateStr + "'",
						"delete from filelog where CreateTime<'" + presDateStr + "'",
						"delete from fileinfo where CreateDate<'" + presDateStr + "'",
						"delete from halog where time<'" + presDateStr + "'",
						"delete from detect_audit where detectTime<'" + presDateStr + "'",
						"delete from patchfix where fixTime<'" + presDateStr + "'",
						"delete from flowalert where alerttime<'" + presDateStr + "'",
						"delete from alarmaudit where createdtime<'" + presDateStr + "'",
						"delete from node_ip_audit where auditTime<'" + presDateStr + "'",
						"delete from approvallog where CreateTime<'" + presDateStr + "'",
						"delete from accessfilelog where CreateTime<'" + presDateStr + "'",
						"delete from usblog where CreateTime<'" + presDateStr + "'",
				};
				
				for (int i = 0; i < sqls.length; i++) {
					st.executeUpdate(sqls[i]);
				}
				
			} catch (SQLException e) {
				logger.error("清理数据库数据出现异常", e);
			} finally {
				try {
					if (st != null) {
						st.close();
					}
					if (conn != null) {
						conn.close();
					}
				} catch (SQLException e) {
					logger.error("关闭数据库连接出现异常",e);
				}

				
				if(HibernateSessionFactory.getSession().isOpen() && HibernateSessionFactory.getSession().getTransaction() != null
						&& HibernateSessionFactory.getSession().getTransaction().isActive()){
					HibernateSessionFactory.getSession().getTransaction().commit();//提交事务
				}
				HibernateSessionFactory.closeSession();//关闭session
			}

		}

	}

	private void cleanBakupFile() {
		File bakDir = new File(SnmpConstants.BAKUP_PATH);
		dateform = new SimpleDateFormat("yyyyMMdd");
		int time = 60;
		
		IBackupinfoBiz infoBiz = new BackupinfoBizImpl();
		IBackupconfigBiz configBiz = new BackupconfigBizImpl();
		Backupconfig info = configBiz.getInfoById(1);
		String keepTime = info.getKeeptime();
		String keepTimeUnit = info.getKeeptimeunit();
		
		File[] files;
		Calendar fileDate;
		try {
			if (bakDir.isDirectory()) {
				files = bakDir.listFiles();
				for (File file : files) {
					String fileName = file.getName();
					if (fileName.startsWith("CD") || fileName.startsWith("cd")) {
						String fileDateStr = fileName.substring(2, 10);
						fileDate = Calendar.getInstance();
						fileDate.setTime(dateform.parse(fileDateStr));
						Calendar presDate = Calendar.getInstance();
						if("M".equalsIgnoreCase(keepTimeUnit)){
							presDate.add(Calendar.MONTH, -Integer.valueOf(keepTime));
						}else if("Y".equalsIgnoreCase(keepTimeUnit)){
							presDate.add(Calendar.YEAR, -Integer.valueOf(keepTime));
						}else{
							logger.info("获取系统备份的保留时间单位出错，使用默认的60天清理");
							presDate.add(Calendar.DAY_OF_MONTH, -time);
						}
						
						if (fileDate.compareTo(presDate) < 0) {
							file.delete();
							//文件删除时同时更新数据库备份文件记录
							List<Backupinfo> backupList = infoBiz.findByProperty("filename", fileName);
							for (Backupinfo backupinfo : backupList) {
								infoBiz.delete(backupinfo);
							}
							
						}
					}

				}

			}
		} catch (Exception e) {
			logger.error("清除备份文件出现异常",e);
		}
	}

	/**
	 * 清理tomcat日志文件（N天前）
	 */
	private void cleanTomcatLogs() {
		dateform = new SimpleDateFormat("yyyy-MM-dd");
		File[] files;
		Calendar fileDate = Calendar.getInstance();
		try {
			if (dir.isDirectory()) {
				files = dir.listFiles();

				// N天前的日期
				Calendar presDate = Calendar.getInstance();
				presDate.add(Calendar.DATE, -ConfFileUtil.CLEAR_DAY);

				Pattern p = Pattern.compile("\\d{4}-\\d{2}-\\d{2}");
				for (File file : files) {
					String fileName = file.getName();
					Matcher m = p.matcher(fileName);

					if (m.find()) {
						MatchResult mr = m.toMatchResult();
						String dateStr = fileName.substring(mr.start(), mr
								.end());
						fileDate.setTime(dateform.parse(dateStr));
						// 删除N天前的日志文件
						if (fileDate.compareTo(presDate) < 0) {
							file.delete();
						}
					}

				}

			}
		} catch (Exception e) {
			logger.error("清除日志文件出现异常",e);
		}
	}

	/*
	 * public static void main(String[] ar) { Timer timer = new Timer();
	 * timer.schedule(new CleanTask(1), 0, 1000 * 60 * 5);
	 * 
	 * 
	 * }
	 */

}
