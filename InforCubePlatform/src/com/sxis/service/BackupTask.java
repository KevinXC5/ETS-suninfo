package com.sxis.service;

import java.io.File;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimerTask;

import org.apache.log4j.Logger;

import com.sxis.biz.common.dao.HibernateSessionFactory;
import com.sxis.biz.system.manage.IBackupinfoBiz;
import com.sxis.biz.system.manage.impl.BackupinfoBizImpl;
import com.sxis.biz.system.po.Backupinfo;
import com.sxis.biz.util.CommonUtil;
import com.sxis.biz.util.ConfFileUtil;

public  class BackupTask extends TimerTask { 
	private static Logger logger = Logger.getLogger(BackupTask.class.getName());
	
	@Override
	public void run() {
		HibernateSessionFactory.getSession().beginTransaction();//开启事务
		
		String Confile = ConfFileUtil.INSTALL_DIR + "conf";
		String downloadFile = ConfFileUtil.DATA_DIR + "download/";
		String confile = ConfFileUtil.PROJECT_DIR + "conf";
//			ConfFileUtil.INSTALL_DIR + "tomcat/myapps/InforCubeWeb/conf";
		String tokenFile = ConfFileUtil.DATA_DIR + "addons/token";
//		String tokenFile1 = ConfFileUtil.DATA_DIR + "addons/token.xml";
//		String tokenConf1 = "/token.properties";
//		String tokenConf2 = "/user.properties";
		String shellCommand = "sh " + ConfFileUtil.INSTALL_DIR + "sh/bak.sh "
				+ Confile + " " + downloadFile + " " + confile + " " + tokenFile;
//				+ " " + tokenFile1 + " " + tokenConf2;
		
		Date date = new Date();
		String nameTime = new String(new SimpleDateFormat("yyyyMMddHHmm").format(date));
		String backTime = new String(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(date));
		
		logger.info("即将执行自动生成备份文件，执行命令为 " + shellCommand);
		boolean res = CommonUtil.executeCommand(shellCommand);
		if(res){
			saveBackinfo(nameTime,backTime);
			logger.info("系统自动生成备份文件成功");
		}
		if(HibernateSessionFactory.getSession().isOpen() && HibernateSessionFactory.getSession().getTransaction() != null
				&& HibernateSessionFactory.getSession().getTransaction().isActive()){
			HibernateSessionFactory.getSession().getTransaction().commit();//提交事务
		}
		HibernateSessionFactory.closeSession();//关闭session
	}
	
	/**
	 * 把自动备份信息保存到数据库中
	 */
	public void saveBackinfo(String nameTime, String backTime){
		IBackupinfoBiz backupBiz = new BackupinfoBizImpl();
		String fileName = "CD" + nameTime + ".tar";
		File f= new File(ConfFileUtil.DATA_DIR + "download/" + fileName);
		if (f.exists() && f.isFile()){
			String fileSize = CommonUtil.sizeConvert(String.valueOf(f.length()));
			if(!"文件太大".equalsIgnoreCase(fileSize)){
			  	Backupinfo backupInfo = new Backupinfo();
				backupInfo.setDate(backTime);
				backupInfo.setFilename(fileName);
				backupInfo.setFilenote("Auto");
				backupInfo.setFilepath(ConfFileUtil.DATA_DIR + "download/");
				backupInfo.setFilesize(fileSize);
				backupInfo.setOperator("");
				backupBiz.save(backupInfo);
			}
		}
	}
}
