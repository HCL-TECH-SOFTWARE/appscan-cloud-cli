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

import com.hcl.appscan.sdk.auth.AuthenticationHandler;
import com.hcl.appscan.sdk.auth.IAuthenticationProvider;
import com.hcl.appscan.sdk.auth.LoginType;


import java.io.Serializable;
import java.net.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class CloudAuthenticationHandler implements IAuthenticationProvider, Serializable {
	private static final Lock lock = new ReentrantLock();
	private final CloudCredentials cloudCredentials;

	public CloudAuthenticationHandler() {
		this.cloudCredentials = new CloudCredentials();
	}

	@Override
	public boolean isTokenExpired() {

		boolean isExpired = false;
		AuthenticationHandler handler = new AuthenticationHandler(this);
		try {
			isExpired = handler.isTokenExpired();
		} catch (Exception e) {
			isExpired = true;
		}
		if (isExpired) {
			lock.lock();
			try {
				isExpired = handler.isTokenExpired();
			} catch (Exception e) {
				isExpired = true;
			}
			if (isExpired) {
				try {
					isExpired = !handler.login(cloudCredentials.getKey(), cloudCredentials.getSecret(), false, LoginType.ASoC_Federated, cloudCredentials.getClientType());
				} catch (Exception e) {
					isExpired = true;
				}
			}
			lock.unlock();
		}
		return isExpired;
	}

	@Override
	public Map<String, String> getAuthorizationHeader(boolean persist) {
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Authorization", "Bearer " + cloudCredentials.getToken().trim());  //$NON-NLS-2$
		if (persist)
			headers.put("Connection", "Keep-Alive");  //$NON-NLS-2$
		return headers;
	}

	@Override
	public String getServer() {
		return cloudCredentials.getServer();
	}

	@Override
	public void saveConnection(String token) {
		cloudCredentials.setToken(token);
	}

	@Override
	public Proxy getProxy() {
		return Proxy.NO_PROXY;
	}

	@Override
	public boolean getacceptInvalidCerts() {
		return false;
	}

	public boolean updateCredentials(String key, String secret) throws Exception {
		if (key == null || key.equals("") || secret == null || secret.length() == 0) return false;
		lock.lock();
		Credentials credentials = LoginUtility.getCredentialsObject(key, secret);
		AuthenticationHandler handler = new AuthenticationHandler(this);
		boolean b;
		try {
			this.cloudCredentials.updateCredentials(key, secret);
			b = handler.login(credentials.getKey(),credentials.getSecret(), true, LoginType.ASoC_Federated, cloudCredentials.getClientType());

		} catch (Exception e) {
			throw e;
		} finally {
			lock.unlock();
		}
		return b;
	}

}