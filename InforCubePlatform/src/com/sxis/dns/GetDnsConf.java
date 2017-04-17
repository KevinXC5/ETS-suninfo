package com.sxis.dns;

import java.io.File;
import java.util.List;

import com.sxis.biz.access.manage.IVlanBiz;
import com.sxis.biz.access.manage.impl.VlanBizImpl;
import com.sxis.biz.access.po.Vlan;
import com.sxis.biz.util.ConfFileUtil;

public class GetDnsConf {
			public final static String  NET_TYPE_VLAN_REG = "vlan-registration"; 
			public final static String  NET_TYPE_VLAN_ISOL = "vlan-isolation"; 
 			public final static String  NETWORK_CONF = ConfFileUtil.NETWORK_CONFIG_FILE;
 			public final static String  Install_dir =  ConfFileUtil.INSTALL_DIR.substring(0, ConfFileUtil.INSTALL_DIR.length()-1);
 			public final static String  Name =  "ifence" ;
 			//general dns configfiles
 			public final static String TEMP_NAMED_CONF = ConfFileUtil.CONFIG_DIR + "named.conf";
 			public final static String TEMP_REGISTRATION_CONF = ConfFileUtil.CONFIG_DIR + "named-registration.ca";
 			public final static String TEMP_ISOLATION_CONF = ConfFileUtil.CONFIG_DIR + "named-isolation.ca";
 			public final static String NAMED_CONF = ConfFileUtil.INSTALL_DIR + "var/conf/named.conf";
 			public final static String REGISTRTION_CONF = ConfFileUtil.INSTALL_DIR + "var/named/named-registration.ca";
 			public final static String ISOLATION_CONF = ConfFileUtil.INSTALL_DIR + "var/named/named-isolation.ca";

 			public static Vlan registrationVlan;
 			public static Vlan isolationVlan;
 			static{
 				IVlanBiz vlanBiz = new VlanBizImpl();
 				List<Vlan> vlans = vlanBiz.getView();
 				int flag = 0;
 				//System.out.println(vlans.size());
 				for (Vlan vlan : vlans) {
					if(vlan.getVlanType().equals(NET_TYPE_VLAN_REG)){
						registrationVlan = vlan;
						flag++;
					}else if(vlan.getVlanType().equals(NET_TYPE_VLAN_ISOL)){
						isolationVlan = vlan;
						flag++;
					}
					if(flag>1){
						 break;
					}
				}
 				
 				
 			};
 			

 			public static void getNamedConf() {
 				//ip--registrationVlan--registration_clients的值
 				String registrationIp = GetDnsConf.registrationVlan.getNetName();
 				int regnetmask = NetWork.getNetMask(GetDnsConf.registrationVlan.getNetmask()) ;
 				//把取得的ip值转换输出
 				String registration_clients = registrationIp + "/" + regnetmask + ";"; 
 				
 				//ip--isolationVlan--得出isolation_clients的值\
 				String isolationIp = GetDnsConf.isolationVlan.getNetName();
 				int isonetmask = NetWork.getNetMask(GetDnsConf.isolationVlan.getNetmask()) ;
 				String isolation_clients = isolationIp + "/" + isonetmask + ";";
 				//生成配置文件
 				File src = new File(TEMP_NAMED_CONF);
 				File path = new File(NAMED_CONF);
 				String cont = Replace.read(src);
 				// 对得到的内容进行处理
 				cont = cont.replaceAll("%%install_dir%%",Install_dir);
 				cont = cont.replaceAll("pf", Name);
 				cont = cont.replaceAll("%%isolation_clients%%", isolation_clients);
 				cont = cont.replaceAll("%%registration_clients%%", registration_clients);
 				//System.out.println(cont);
 				// 更新源文件
 				Replace.write(cont, path);
 				//System.out.println(Replace.write(cont, path));
 			}
 			
 			public static void getIsolationConf() {
 				
 				//取得的值赋给变量
 				String domain = ConfFileUtil.getFromIfence("general" , "domain");
 				String hostname = ConfFileUtil.getFromIfence("general" , "hostname");
 				String incharge =  Name + "." + hostname + "." + domain;
 				//拿到隔离vlan的ip值
 				String isolationIp = GetDnsConf.isolationVlan.getDomainServerIp();;
 				String[] tt = new String[200];
 				tt = isolationIp.trim().split("\\.");
 				String PTR_blackhole = tt[3] + "." + tt[2] + "." + tt[1] + "." + tt[0];
 				File src = new File(TEMP_ISOLATION_CONF);
 				File path = new File(ISOLATION_CONF);
 				String cont = Replace.read(src);
 			//	System.out.println(cont);
 				// 对得到的内容进行处理
 				cont = cont.replaceAll("%%hostname%%", hostname);
 				cont = cont.replaceAll("%%incharge%%", incharge);
 				cont = cont.replaceAll("%%A_blackhole%%", isolationIp);
 				cont = cont.replaceAll("%%PTR_blackhole%%", PTR_blackhole);
 				Replace.write(cont, path);
 			//	System.out.println(Replace.write(cont, path));
 			}
 			
 			public static void getRegistrationConf() {
 				
 				//取得的值赋给变量
 				String domain = ConfFileUtil.getFromIfence("general" , "domain");
 				String hostname = ConfFileUtil.getFromIfence("general" , "hostname");
 				String incharge =  Name + "." + hostname + "." + domain;
 				//拿到注册vlan的ip值
 				String registrationIp = GetDnsConf.registrationVlan.getDomainServerIp();
 				//对获得的ip 转换成逆向输出
 				String[] tt = new String[200];
 				tt = registrationIp.trim().split("\\.");
 				String PTR_blackhole = tt[3] + "." + tt[2] + "." + tt[1] + "." + tt[0];
 				
 				//写入变量生成配置文件
 				File src = new File(TEMP_REGISTRATION_CONF);
 				File path = new File(REGISTRTION_CONF);
 				String cont = Replace.read(src);
 				// 对得到的内容进行处理
 				cont = cont.replaceAll("%%hostname%%", hostname);
 				cont = cont.replaceAll("%%incharge%%", incharge);
 				cont = cont.replaceAll("%%A_blackhole%%", registrationIp);
 				cont = cont.replaceAll("%%PTR_blackhole%%", PTR_blackhole);
 				// 更新源文件
 				Replace.write(cont, path);
 				//System.out.println(Replace.write(cont, path));

 			}
 			
// 			public static void main(String[] args) { 
// 				/*VlanDAO vlan = new VlanDAOImpl ();
// 				for (Vlan vlan1: vlan.getView()) {
// 					System.out.println(vlan1.getNetName());
// 				}*/
// 				//System.out.println(GetDnsConf.isolationVlan.getVlanType()+"dns:"+GetDnsConf.isolationVlan.getDomainServerIp());
// 				//System.out.println(ConfFileUtil.getFromIfence("general" , "hostname"));
// 				//System.out.println(ConfFileUtil.getFromIfence("general" , "domain"));
// 				System.out.println(GetDnsConf.isolationVlan.getNetName()+"dns:"+GetDnsConf.isolationVlan.getDomainServerIp());
// 				System.out.println( NetWork.getNetMask(GetDnsConf.isolationVlan.getNetmask()));
// 			}
}