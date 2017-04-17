package com.sxis.dns;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import org.apache.log4j.Logger;

public class Replace {
	private static Logger logger = Logger.getLogger(Replace.class.getName());

	// private static final Reader StringRpl = null;

	public static String read(File src) {
		StringBuffer res = new StringBuffer();
		String line = null;
		BufferedReader reader = null;
		try {
			reader = new BufferedReader(new FileReader(src));
			while ((line = reader.readLine()) != null) {
				res.append(line + "\n");
			}
			reader.close();
		} catch (FileNotFoundException e) {
			logger.error("读取文件出现异常", e);
		} catch (IOException e) {
			logger.error("读取文件出现异常", e);
		}finally{
			if(reader != null){
				try {
					reader.close();
				} catch (IOException e) {
					logger.error("关闭读取文件流出现异常", e);
				}
			}
			
		}
		return res.toString();
	}

	public static boolean write(String cont, File dist) {
		BufferedWriter writer = null;
		try {
			writer = new BufferedWriter(new FileWriter(dist));
			writer.write(cont);
			writer.flush();
			writer.close();
			return true;
		} catch (IOException e) {
			logger.error("修改文件出现异常", e);
			return false;
		}finally{
			if(writer != null){
				try {
					writer.close();
				} catch (IOException e) {
					logger.error("关闭写文件流出现异常", e);
				}
			}
		}
	}

	public void StringRpl() {

	}

	/*
	 * public static void main(String[] args) {
	 * 
	 * File src = new File(ActConstant.DEFAULT_NAMED_CONF_PATH); String cont =
	 * Replace.read(src); System.out.println(cont); //对得到的内容进行处理 cont =
	 * cont.replaceAll("pf", "public"); System.out.println(cont); //更新源文件 //
	 * System.out.println(Replace.write(cont, src)); }
	 */

}