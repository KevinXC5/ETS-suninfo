package com.sxis.trap;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.sxis.biz.access.po.TrapGlobalSetting;

public class TrapServer {

	private TrapServer() {
		
	}
	
	private static TrapServer instance = new TrapServer();
	
	public static TrapServer getInstance() {
		return instance;
	}
	
	/**
	 * 所有要启动接收Trap信息的服务端口.
	 */
	private Set<Integer> allPorts = new HashSet<Integer>();
	
	/**
	 * 端口与共同体的映射. 在指定端口只接收相应集合的共同体的Trap信息.
	 */
	private ConcurrentHashMap<Integer, List<String>> portCommunityMapping = new ConcurrentHashMap<Integer, List<String>>();
	
	/**
	 * 没有成功启动接收Trap信息的服务端口.
	 */
	private Set<Integer> unruningPorts = new HashSet<Integer>();
	
	/**
	 * 成功启动接收Trap信息的服务端口.
	 */
	private Set<Integer> runningPorts = new HashSet<Integer>();
	
	/**
	 * 接收Trap信息的服务端口与使用的线程池关联映射, 以便停止正在接收Trap信息的服务端口.
	 */
	private ConcurrentHashMap<Integer, MultiThreadTrapReceiver> mtrs = new ConcurrentHashMap<Integer, MultiThreadTrapReceiver>();
	
	public void setTrapConfig(TrapGlobalSetting trapGlobalSetting) {
		Map<String, List<String>> globalSettingMap = trapGlobalSetting.getMap();
		Set<String> keys = globalSettingMap.keySet();
		allPorts.clear();
		for (String key : keys) {
			int port = Integer.parseInt(key);
			allPorts.add(port);
			List<String> communitys = globalSettingMap.get(key);
			List<String> tempCommunitys = new ArrayList<String>();
			for (String community:communitys){
				if (!tempCommunitys.contains(community.trim())){
					tempCommunitys.add(community.trim());
				}
			}
			portCommunityMapping.put(port, tempCommunitys);
		}
		updateRunningPorts();
		updateUnruningPorts();
	}

	private void updateUnruningPorts() {
		unruningPorts.clear();
		for (Integer port : allPorts) {
			if (!runningPorts.contains(port)) {
				List<String> communitys = portCommunityMapping.get(port);
				startupTrap(port, communitys);
			}
		}
	}

	private void startupTrap(int port, List<String> communitys) {
		MultiThreadTrapReceiver mtr = new MultiThreadTrapReceiver("127.0.0.1", port, communitys);
		try {
			mtr.run();
			mtrs.put(port, mtr);
			runningPorts.add(port);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
//	private void stopServerOnPort(int port) {
//		
//	}

	private void updateRunningPorts() {
		// TODO Auto-generated method stub
		
	}
}
