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



import java.io.Serializable;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class CloudCredentials implements Serializable {
	private static final Lock lock = new ReentrantLock();

	public CloudCredentials() {
		this.clientType = LoginUtility.getClientType();
	}

	public Credentials getCredentials() {
		return credentials;
	}

	public void setCredentials(Credentials credentials) {
		this.credentials = credentials;
	}

	private Credentials credentials;
	private String token;
	private String clientType;


	public String getServer() {
		return LoginUtility.getServer(getKey());
	}


	public String getKey() {
		return credentials.getKey();
	}

	public String getSecret() {
		return credentials.getSecret();
	}

	public String getToken() {
		return token == null ? "" : token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public String getClientType() {
		return clientType;
	}

	public void updateCredentials(String key, String secret) {
		lock.lock();
		this.credentials = new Credentials(key, secret);
		lock.unlock();
	}


	public void setClientType(String clientType) {
		this.clientType = clientType;
	}
}