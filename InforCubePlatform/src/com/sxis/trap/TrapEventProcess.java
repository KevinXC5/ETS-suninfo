package com.sxis.trap;

import java.util.Date;
import java.util.Vector;

import org.snmp4j.CommandResponderEvent;
import org.snmp4j.PDU;
import org.snmp4j.PDUv1;
import org.snmp4j.smi.VariableBinding;

import com.sxis.biz.access.manage.IPollingTrapService;
import com.sxis.biz.access.po.TrapMessage;
import com.sxis.biz.access.po.V1TrapMessage;
import com.sxis.biz.access.po.V2TrapMessage;

public class TrapEventProcess implements Runnable {
	
	private IPollingTrapService pollingTrapService = null;

	/**
	 * 要处理的Trap事件.
	 */
	CommandResponderEvent trapEvent = null;
	
	public TrapEventProcess(CommandResponderEvent trapEvent) {
		this.trapEvent = trapEvent;
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public void run() {
		TrapMessage trapMessage = new TrapMessage();
		
		// 封装trapMessage
		if (trapEvent == null) {
			return;
		}
		String sourceIPAddress = trapEvent.getPeerAddress().toString();
		sourceIPAddress = sourceIPAddress.substring(0, sourceIPAddress.indexOf("/"));
		PDU pdu = trapEvent.getPDU();

		String timeStamp = "";
		String vbs = "";

		if (pdu.getType() == PDU.V1TRAP) {
			PDUv1 pduv1 = (PDUv1) pdu;
			String enterpriseOID = pduv1.getEnterprise().toString();
			int genericType = pduv1.getGenericTrap();
			int specificType = pduv1.getSpecificTrap();
			long timestamp = pduv1.getTimestamp();
			vbs = pduv1.getVariableBindings().toString();
			vbs = vbs.substring(1, vbs.length() - 1);
			V1TrapMessage v1TrapMessage = (V1TrapMessage) trapMessage;
			v1TrapMessage.setGathererTime(new Date());
			v1TrapMessage.setTimeStamp(longTimeToString(timestamp));
			v1TrapMessage.setSourceIPAddress(sourceIPAddress);
			v1TrapMessage.setTrapVersion("V1");
			v1TrapMessage.setEnterpriseOID(enterpriseOID);
			v1TrapMessage.setGenericType(genericType);
			v1TrapMessage.setSpecificType(specificType);
			v1TrapMessage.setVbs(vbs);
			pollingTrapService.sendTrapMessage(v1TrapMessage);
		}
		
		else if (pdu.getType() == PDU.TRAP) {
			Vector<VariableBinding> vs = pdu.getVariableBindings();
			vbs = vs.toString();
			vbs = vbs.substring(1, vbs.length() - 1);
			String trapOID = "";
			int errorIndex = pdu.getErrorIndex();
			int errorStatus = pdu.getErrorStatus();
			for (VariableBinding v : vs) {
				String oid = v.getOid().toString().trim();
				if (oid.equals("1.3.6.1.2.1.1.3.0")) {
					timeStamp = v.getVariable().toString();
				}
				if (oid.equals("1.3.6.1.6.3.1.1.4.1.0")) {
					trapOID = v.getVariable().toString().trim();
				}
				if (timeStamp.length() > 0 && trapOID.length() > 0){
					break;
				}
			}
			V2TrapMessage v2TrapMessage = (V2TrapMessage) trapMessage;
			v2TrapMessage.setGathererTime(new Date());
			v2TrapMessage.setTimeStamp(timeStamp);
			v2TrapMessage.setSourceIPAddress(sourceIPAddress);
			v2TrapMessage.setTrapVersion("V2");
			v2TrapMessage.setTrapOID(trapOID);
			v2TrapMessage.setErrorIndex(errorIndex);
			v2TrapMessage.setErrorStatus(errorStatus);
			v2TrapMessage.setVbs(vbs);
			pollingTrapService.sendTrapMessage(v2TrapMessage);
		}
	}
	
	private String longTimeToString(long timestamp) {
		long days = timestamp / 86400000;
		timestamp = timestamp % 86400000;
		long hours = timestamp / 3600000;
		timestamp = timestamp % 3600000;
		long minutes = timestamp / 60000;
		timestamp = timestamp % 60000;
		long seconds = timestamp / 1000;
		long milliseconds = timestamp % 1000;
		return days + " days, " + hours + ":" + minutes + ":" + seconds + "."
				+ milliseconds;
	}

}
