package com.sxis.trap;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.snmp4j.CommandResponderEvent;

public final class MessageProcessSend {
	/**
	 * 线程池. 用来处理提交的Trap和Syslog事件.
	 * 该线程池核心线程数为2, 最大线程数为5, 存活时间6000秒, 队列最大长度100,
	 * 队列策略是抛弃较早的任务.
	 */
	private ThreadPoolExecutor threadPool = new ThreadPoolExecutor(2, 5, 6000,
			TimeUnit.SECONDS, new ArrayBlockingQueue<Runnable>(100),
			new ThreadPoolExecutor.DiscardOldestPolicy());
	
	private MessageProcessSend() {

	}
	
	private static MessageProcessSend instance = new MessageProcessSend();
	
	public static MessageProcessSend getInstance() {
		return instance;
	}
	
	public void submitTrapEvent(CommandResponderEvent trapEvent) {
		Runnable task = new TrapEventProcess(trapEvent);
		threadPool.submit(task);
	}
}
