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

package com.hcl.appscan.cli.scanners;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.auth.IAuthenticationProvider;
import com.hcl.appscan.sdk.http.HttpClient;
import com.hcl.appscan.sdk.http.HttpResponse;
import org.apache.wink.json4j.JSONArtifact;
import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.net.URL;

/**
 * Provides scan service utilities.
 */
public class ValidationUtil implements CoreConstants {
	

	/**
	 * Checks if the given url is valid for scanning.
	 * 
	 * @param url The url to test.
	 * @param provider The IAuthenticationProvider for authentication.
	 * @return True if the url is valid. False is returned if the url is not valid, the request fails, or an exception occurs.
	 */
	public static boolean isValidUrl(String url, IAuthenticationProvider provider) {
		return isValidUrl(url, provider, Proxy.NO_PROXY);
	}
	
	/**
	 * Checks if the given url is valid for scanning.
	 * 
	 * @param url The url to test.
	 * @param provider The IAuthenticationProvider for authentication.
	 * @param proxy The proxy to use for the connection.
	 * @return True if the url is valid. False is returned if the url is not valid, the request fails, or an exception occurs.
	 */
	public static boolean isValidUrl(String url, IAuthenticationProvider provider, Proxy proxy) {
		String request_url = provider.getServer() + API_IS_VALID_URL;

		try {
			JSONObject body = new JSONObject();
			body.put(URL, url);
			Map<String, String> request_headers = provider.getAuthorizationHeader(true);
			request_headers.put("Content-type","application/json");
			HttpClient client = new HttpClient(provider.getProxy(), provider.getacceptInvalidCerts());
			HttpResponse response = client.post(request_url, request_headers, body.toString());

			if (response.isSuccess()) {
				JSONArtifact responseContent = response.getResponseBodyAsJSON();
				if (responseContent != null) {
					JSONObject object = (JSONObject) responseContent;
					return object.getBoolean(IS_VALID);
				}
			}
		} catch (IOException | JSONException e) {
			// Ignore and return false.
		}
		
		return false;
	}

	public static boolean checkASoCConnectivity(String urlString,boolean allowUntrusted) {
		try {
			URL url = new URL(urlString);
			HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
			if((connection != null) && allowUntrusted) {
				bypassSSL((HttpsURLConnection)connection);
			}
			assert connection != null;
			connection.setRequestMethod("HEAD"); // Using the HEAD request method for a faster check
			int responseCode = connection.getResponseCode();

			if (responseCode == HttpURLConnection.HTTP_OK) {
				return true;
			} else {
				return false;
			}

		} catch (Exception e) {
			// Ignore and return false.
		}
		return false;
	}

	private static void bypassSSL(HttpsURLConnection conn)  {
		conn.setHostnameVerifier(new HostnameVerifier() {
			@Override
			public boolean verify(String hostname, SSLSession session) {
				return true;
			}
		});

		TrustManager[] trustManagers = new TrustManager[] { new X509TrustManager() {

			private X509Certificate[] x509Certificates = new X509Certificate[0];

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return x509Certificates;
			}

			@Override
			public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				// do nothing
			}

			@Override
			public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				// do nothing
			}
		}};

		try {
			SSLContext context = SSLContext.getInstance("TLSv1.2"); //$NON-NLS-1$
			context.init(null, trustManagers, null);
			conn.setSSLSocketFactory(context.getSocketFactory());
		} catch (NoSuchAlgorithmException | KeyManagementException e) {
			//Ignore. The connection should fail.
		}
	}
}
