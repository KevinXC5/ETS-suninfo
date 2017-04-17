package com.sxis.service;

import java.util.TimerTask;

import com.sxis.biz.baseinfo.paramconfig.manage.ISwMgmtInfoBiz;
import com.sxis.biz.baseinfo.paramconfig.manage.impl.SwMgmtInfoBizImpl;
import com.sxis.biz.switches.manage.ISnmpInfoBiz;
import com.sxis.biz.switches.manage.impl.SnmpInfoBizImpl;

public class SwitchScanTask extends TimerTask {

	@Override
	public void run() {
		ISnmpInfoBiz sib = new SnmpInfoBizImpl();
		ISwMgmtInfoBiz sw = new SwMgmtInfoBizImpl();
		sw.delSW();
		sib.executeScan();
	}
	
}
