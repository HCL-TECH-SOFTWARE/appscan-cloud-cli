/*
 * *
 *  * @ Copyright HCL Technologies Ltd. 2023.
 *  * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 *
 */

package com.hcl.appscan.cli.auth;



import java.io.Serializable;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class CloudCredentials implements Serializable {
	private static final Lock lock = new ReentrantLock();

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