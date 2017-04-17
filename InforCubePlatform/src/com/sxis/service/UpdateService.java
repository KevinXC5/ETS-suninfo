package com.sxis.service;

import com.sxis.biz.common.dao.HibernateSessionFactory;
import com.sxis.biz.sysconf.util.SystemUpdateUtil;

public class UpdateService {
	public static void main(String[] args) {
		
		//更新模板文件
		SystemUpdateUtil.updateTemplates();
		
		if(HibernateSessionFactory.getSession().isOpen() && HibernateSessionFactory.getSession().getTransaction() != null
				&& HibernateSessionFactory.getSession().getTransaction().isActive()){
			HibernateSessionFactory.getSession().getTransaction().commit();//提交事务
		}
		HibernateSessionFactory.closeSession();//关闭session
	}
}
