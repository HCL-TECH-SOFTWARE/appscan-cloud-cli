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

import java.util.*;

public class DynamicAnalyzer extends Scanner {

	private static final String DYNAMIC_ANALYZER = "Dynamic Analyzer"; 

	private String m_presenceId;
	private String m_scanFile;
	private String m_scanType;
	private String m_optimization;
	private String m_extraField;
	private String m_loginType;
	private String m_loginUser;
	private String m_loginPassword;
	private String m_trafficFile;


	public DynamicAnalyzer(String target) {
		this(target, false, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY);
	}


	public DynamicAnalyzer(String target, boolean hasOptions, String presenceId, String scanFile, String scanType, String optimization, String extraField, String loginUser, String loginPassword, String trafficFile, String loginType) {
		super(target, hasOptions);
		m_presenceId = presenceId;
		m_scanFile = scanFile;
		m_scanType = scanFile != null && !scanFile.equals(EMPTY) ? CUSTOM : scanType;
		m_optimization = optimization;
		m_extraField = extraField;
		m_loginUser = loginUser;
		m_loginPassword = loginPassword;
		m_trafficFile = trafficFile;
		m_loginType = loginType;
	}



	public void setLoginUser(String loginUser) {
		m_loginUser = loginUser;
	}

	public String getLoginUser() {
		return m_loginUser;
	}


	public void setLoginPassword(String loginPassword) {
		m_loginPassword = loginPassword;
	}

	public String getLoginPassword() {
		return m_loginPassword;
	}


	public void setPresenceId(String presenceId) {
		m_presenceId = presenceId;
	}

	public String getPresenceId() {
		return m_presenceId;
	}


	public void setScanFile(String scanFile) {
		m_scanFile = scanFile;
	}

	public String getScanFile() {
		return m_scanFile;
	}


	public void setScanType(String scanType) {
		m_scanType = m_scanFile != null && !m_scanFile.equals(EMPTY) ? CUSTOM : scanType;
	}

	public String getScanType() {
		return m_scanType;
	}


	public void setOptimization(String optimization) {
		if(optimization != null) {
			m_optimization = mapOldtoNewOptLevels(optimization);
		} else {
			m_optimization = optimization;
		}
	}

	public String getOptimization() {
		m_optimization = mapOldtoNewOptLevels(m_optimization);
		return m_optimization;
	}


	public void setExtraField(String extraField) {
		m_extraField = extraField;
	}

	public String getExtraField() {
		return m_extraField;
	}


	public void setLoginType(String loginType) {
			m_loginType =loginType;
	}

	public String getLoginType() {
		return m_loginType;
	}


	public void setTrafficFile(String trafficFile) {
		if (RECORDED.equals(m_loginType))
			m_trafficFile = trafficFile;
	}

	public String getTrafficFile() {
		return m_trafficFile;
	}

	@Override
	public String getType() {
		return DYNAMIC_ANALYZER;
	}

	public String isLoginTypes(String loginTypeName) {
		if (m_loginType != null) {
			return m_loginType.equalsIgnoreCase(loginTypeName) ? "true" : "";
		} else if(!(((m_loginUser.equals(""))) && m_loginPassword.equals(""))){
			m_loginType = AUTOMATIC;
			return "true";
		} else if (loginTypeName.equals(NONE)) { //Default
			return "true";
		} else {
			return "";
		}
	}

	public String upgradeLoginScenario(){
		if(!(((m_loginUser.equals(""))) || m_loginPassword.equals(""))){
			return m_loginType = AUTOMATIC;
		} else {
			return m_loginType = NONE;
		}
	}

	@Override
	public Map<String, String> getProperties()  {
		Map<String, String> properties = new HashMap<String, String>();

			properties.put(TARGET, getTarget());
			properties.put(SCAN_FILE, m_scanFile);
			//properties.put(EXTRA_FIELD, m_extraField);
			if(m_loginType == null || m_loginType.equals("")){
				m_loginType = upgradeLoginScenario();
			}
				if (RECORDED.equals(m_loginType)) {
					properties.put(TRAFFIC_FILE, m_trafficFile);
					if (m_trafficFile == null || m_trafficFile.equals("")) {
						throw new IllegalArgumentException("A login sequence file is required to scan your application..");
					} else if ((!((m_trafficFile).toLowerCase().endsWith(TEMPLATE_EXTENSION3)))){
						throw new IllegalArgumentException(" The login sequence file format is invalid. Only Config file extension is supported.");
					}
				} else if (AUTOMATIC.equals(m_loginType)) {
					properties.put(LOGIN_USER, m_loginUser);
					properties.put(LOGIN_PASSWORD, m_loginPassword);
					if(m_loginUser.equals("") || m_loginPassword.equals("")){
						throw new IllegalArgumentException("Username and password are required to scan your application.");
					}
				}

		properties.put(LOGIN_TYPE,m_loginType);
		properties.put(SCAN_TYPE, m_scanType);
		properties.put(TEST_OPTIMIZATION_LEVEL, m_optimization);
		//properties.put(PRESENCE_ID, m_presenceId);

		return properties;
	}

	private String mapOldtoNewOptLevels(String optimization) //Backward Compatibility
	{
		if(optimization != null) {
			if(optimization.equals(NORMAL)) {
				m_optimization = NO_OPTIMIZATION;
			} else if(optimization.equals(OPTIMIZED)) {
				m_optimization = FAST;
			} else {
				m_optimization = optimization;
			}
		}
		return m_optimization;
	}


}

