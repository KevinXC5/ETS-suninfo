package com.sxis.dns;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import com.sxis.biz.util.ConfFileUtil;

public class Start {
	public static BufferedReader cmdExe(String cmd) throws IOException {

		Process ps = Runtime.getRuntime().exec(cmd);
		BufferedReader br = new BufferedReader(new InputStreamReader(ps
				.getInputStream()));
		return br;
	}

//	public static void main(String[] args) throws IOException {
//		// 调用getDNSConf中的静态类方法 生成dns相关配置
//		GetDnsConf.getNamedConf();
//		GetDnsConf.getRegistrationConf();
//		GetDnsConf.getIsolationConf();
//		String cmd = "service named status";
//		String cmd1 = "/usr/sbin/named -c " + ConfFileUtil.INSTALL_DIR + "var/conf/named.conf";
//		String result1 = null;
//		String result2 = null;
//		try {
//			result1 = cmdExe(cmd).toString();
//			result2 = cmdExe(cmd1).toString();
//			// System.out.println(result2);
//		} catch (IOException e) {
//
//		}
//
//	}
}
