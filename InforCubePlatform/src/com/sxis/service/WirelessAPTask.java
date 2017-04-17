package com.sxis.service;

import java.util.TimerTask;

import com.sxis.biz.switches.manage.ISnmpInfoBiz;
import com.sxis.biz.switches.manage.impl.SnmpInfoBizImpl;

public class WirelessAPTask extends TimerTask {

	@Override
	public void run() {
		ISnmpInfoBiz sib = new SnmpInfoBizImpl();
		sib.updateWirelessUnregDevice();
	}
	
}
