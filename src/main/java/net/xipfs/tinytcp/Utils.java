package net.xipfs.tinytcp;

/**
 * 工具类
 * 
 * @author root
 *
 */
public class Utils {
	/**
	 * 将 byte 数组以16进制的形式输出
	 * @param b
	 */
	public static void printHexString(byte[] b){
		for (int i = 0; i < b.length; i++){
			String hex = Integer.toHexString(b[i] & 0xFF);
			if(hex.length() == 1){
				hex = '0' + hex;
			}
			System.out.print(hex.toUpperCase()+" ");
		}
		System.out.println("");
	}
}
