package com.sxis.service;


public class InitializePolling {
//	private static Logger logger = Logger.getLogger(InitializePolling.class.getName());
//	private boolean isInitializedTrapServer = false;
	
	private InitializePolling() {
		
	}
	
	private static InitializePolling instance = new InitializePolling();
	
	public static InitializePolling getInstance() {
		return instance;
	}
	
//	public boolean initialize() {
//		// 由PollingInfo构造TrapGlobalSetting
//		try {
//			TrapGlobalSetting trapGlobalSetting = new TrapGlobalSetting();
//			List<String> communitys = new ArrayList<String>();
//			communitys.add("public");
//			communitys.add("private");
//			Map<String, List<String>> map = new HashMap<String, List<String>>();
//			map.put("162", communitys);
//			trapGlobalSetting.setMap(map);
//			/*
//			TrapServer trapServer = TrapServer.getInstance();
//			trapServer.setTrapConfig(trapGlobalSetting);
//			*/
//			isInitializedTrapServer = true;
//			
//			MultiThreadTrapReceiver trapReceiver = new MultiThreadTrapReceiver("172.18.4.34", 162, communitys);
//			try {
//				trapReceiver.run();
//			} catch (Exception e) {
//				e.printStackTrace();
//			}
//		} catch (RuntimeException e) {
//			isInitializedTrapServer = false;
//		}
//		if (isInitializedTrapServer) {
//			logger.info("Trap监听服务初始化成功.");
//		} else {
//			logger.warn("Trap监听服务初始化失败.");
//		}
//		return isInitializedTrapServer;
//	}
}
