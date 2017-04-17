package com.sxis.dhcp;

/**
 * @author xxm
 * 

 */

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.krakenapps.pcap.Protocol;
import org.krakenapps.pcap.decoder.dhcp.DhcpDecoder;
import org.krakenapps.pcap.decoder.dhcp.DhcpMessage;
import org.krakenapps.pcap.decoder.dhcp.DhcpProcessor;
import org.krakenapps.pcap.live.PcapDevice;
import org.krakenapps.pcap.live.PcapDeviceManager;
import org.krakenapps.pcap.live.PcapDeviceMetadata;
import org.krakenapps.pcap.util.PcapLiveRunner;

import com.sxis.biz.dhcp.manage.IDhcpBiz;
import com.sxis.biz.dhcp.manage.impl.DhcpBizImpl;


public class DhcpProcess {
	private static Logger logger = Logger
			.getLogger(DhcpProcess.class.getName());

	public static void dhcpListener() throws IOException {

		// 创建监听器列表

		List<PcapDevice> pcapList = new ArrayList<PcapDevice>();

		// 创建线程列表

		List<PcapLiveRunner> runnerlist = new ArrayList<PcapLiveRunner>();
		PcapDevice device = null;

		// 获取设备网卡列表，并为每一块网卡设置一个监听器

		for (PcapDeviceMetadata metadata : PcapDeviceManager
				.getDeviceMetadataList()) {
			try {
				device = PcapDeviceManager.open(metadata.getName(),
						Integer.MAX_VALUE);
			} catch (IOException e) {
				logger.error("添加网卡时出错" , e);
			}
			pcapList.add(device);
		}

		// 创建dhcp报文解析器，用于解析dhcp报文

		DhcpDecoder dhcp = new DhcpDecoder();

		for (PcapDevice devicename : pcapList) {
			PcapLiveRunner runner = new PcapLiveRunner(devicename);
			runnerlist.add(runner);
			runner.setUdpProcessor(Protocol.DHCP, dhcp);

		}

		// 重写DhcpProcessor方法

		dhcp.register(new DhcpProcessor() {
			IDhcpBiz dhcp = new DhcpBizImpl ();

			@Override
			public void process(DhcpMessage msg) {
				dhcp.DhcpPacketProcess(msg);
			}

		});

		// 为每个网卡创建一个线程

		for (PcapLiveRunner startRunner : runnerlist) {
			Thread t1 = new Thread(startRunner);
			t1.start();
		}

	}
}
