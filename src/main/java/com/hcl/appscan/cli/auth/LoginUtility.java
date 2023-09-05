/*
 * *
 *  * @ Copyright HCL Technologies Ltd. 2023.
 *  * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 *
 */

package com.hcl.appscan.cli.auth;


import com.hcl.appscan.cli.auth.Credentials;
import com.hcl.appscan.sdk.utils.SystemUtil;


public class LoginUtility {

	public static Credentials getCredentialsObject(String key, String secret) {
		return new Credentials(key, secret);
	}

	public static String getServer(String key) {
		return SystemUtil.getServer((key == null ? "" : key));
	}

}