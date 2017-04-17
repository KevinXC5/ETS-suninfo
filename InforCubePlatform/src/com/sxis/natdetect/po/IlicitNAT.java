package com.sxis.natdetect.po;

/**
 * 非法NAT设备实体类
 * @author KevinXC
 * @date 2014-3-27
 */
public class IlicitNAT {
	/** 源ip地址 */
	private String ip;
	
	/** ip报文 ttl 字段值 */
	private int ttl;
	
	/** 记录上一次ip报文中的id号 */
	private int lastId;
	
	/** true 代表确认为NAT设备，false 代表不确定 */
	private boolean isNAT;
	
	public IlicitNAT() {
		super();
	}

	public IlicitNAT(String ip, int ttl, int lastId, boolean isNAT) {
		super();
		this.ip = ip;
		this.ttl = ttl;
		this.lastId = lastId;
		this.isNAT = isNAT;
	}

	public String getIp() {
		return ip;
	}

	public void setIp(String ip) {
		this.ip = ip;
	}

	public int getTtl() {
		return ttl;
	}

	public void setTtl(int ttl) {
		this.ttl = ttl;
	}

	public int getLastId() {
		return lastId;
	}

	public void setLastId(int lastId) {
		this.lastId = lastId;
	}

	public boolean isNAT() {
		return isNAT;
	}

	public void setNAT(boolean isNAT) {
		this.isNAT = isNAT;
	}
}
