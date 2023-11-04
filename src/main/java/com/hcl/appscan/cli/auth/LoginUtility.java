/*
 *
 * Copyright 2023 HCL America, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * /
 */

package com.hcl.appscan.cli.auth;



import com.hcl.appscan.cli.constants.CLIConstants;
import com.hcl.appscan.sdk.utils.SystemUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class LoginUtility {

	private static final Logger logger = LoggerFactory.getLogger(LoginUtility.class);
	private static String clientType;

	public static Credentials getCredentialsObject(String key, String secret) {
		return new Credentials(key, secret);
	}

	public static String getServer(String key) {
		return SystemUtil.getServer((key == null ? "" : key));
	}

	public static String getClientType() {
		String clientName;
		String version;
		String osName;
		if (clientType == null) {
			if (System.getenv().containsKey("APPSCAN_CLIENT") && !System.getenv("APPSCAN_CLIENT").isBlank()) {
				clientName = System.getenv("APPSCAN_CLIENT");
			}else{
				//fallback to default clientName
				clientName = CLIConstants.APPSCAN_CLOUD_CLI;
			}
			if (System.getenv().containsKey("APPSCAN_CLIENT_VERSION") && !System.getenv("APPSCAN_CLIENT_VERSION").isBlank() ) {
				version = System.getenv("APPSCAN_CLIENT_VERSION");
			}else{
				//fallback to cli version
				version = LoginUtility.class.getPackage().getImplementationVersion();
			}

			// If running in an IDE, the version might not be available
			if (version == null) {
				version = "dev";
			}
			osName = System.getProperty("os.name");
			osName = osName == null ? "" : osName.toLowerCase().trim().split(" ")[0];
			if (clientName.isBlank() && osName.isBlank())
				clientType = null;
			else{
				clientType = clientName + "-" + osName + "-" + version.toLowerCase();
				clientType = clientType.replaceAll("-snapshot$", "");
			}

		}
		return sanitizeClientType(clientType);
	}

	public static String sanitizeClientType(String clientType) {
		if (clientType == null) {
			return null;
		}

		String regex = "[^a-zA-Z0-9\\-._]";

		return clientType.replaceAll(regex, "");
	}


}