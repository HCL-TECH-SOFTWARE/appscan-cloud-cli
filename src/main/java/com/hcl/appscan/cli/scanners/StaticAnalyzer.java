/*
 *
 * Copyright HCL Technologies Ltd. 2026
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

import java.util.HashMap;
import java.util.Map;

public class StaticAnalyzer extends Scanner {

	private static final long serialVersionUID = 1L;

	private boolean m_openSourceOnly;
	private boolean m_sourceCodeOnly;
	private boolean m_includeSCA;
	private String m_scanMethod;
	private String m_scanSpeed;
	private boolean m_rescan;
	private String m_scanId;

	public StaticAnalyzer(String target) {
		this(target, false, false, false, true, CoreConstants.CREATE_IRX, null, false, null);
	}

	public StaticAnalyzer(String target, boolean hasOptions, boolean openSourceOnly,
						  boolean sourceCodeOnly, boolean includeSCA, String scanMethod,
						  String scanSpeed, boolean rescan, String scanId) {
		super(target, hasOptions);
		m_openSourceOnly = openSourceOnly;
		m_sourceCodeOnly = sourceCodeOnly;
		m_includeSCA = includeSCA;
		m_scanMethod = scanMethod;
		m_scanSpeed = scanSpeed;
		m_rescan = rescan;
		m_scanId = scanId;
	}

	public boolean isOpenSourceOnly() {
		return m_openSourceOnly;
	}

	public void setOpenSourceOnly(boolean openSourceOnly) {
		m_openSourceOnly = openSourceOnly;
	}

	public boolean isSourceCodeOnly() {
		return m_sourceCodeOnly;
	}

	public void setSourceCodeOnly(boolean sourceCodeOnly) {
		m_sourceCodeOnly = sourceCodeOnly;
	}

	public boolean isIncludeSCA() {
		return m_includeSCA;
	}

	public void setIncludeSCA(boolean includeSCA) {
		m_includeSCA = includeSCA;
	}

	public String getScanMethod() {
		return m_scanMethod;
	}

	public void setScanMethod(String scanMethod) {
		m_scanMethod = scanMethod;
	}

	public String getScanSpeed() {
		return m_scanSpeed;
	}

	public void setScanSpeed(String scanSpeed) {
		m_scanSpeed = scanSpeed;
	}

	public boolean isRescan() {
		return m_rescan;
	}

	public void setRescan(boolean rescan) {
		m_rescan = rescan;
	}

	public String getScanId() {
		return m_scanId;
	}

	public void setScanId(String scanId) {
		m_scanId = scanId;
	}

	@Override
	public String getType() {
		return STATIC_ANALYZER;
	}

	@Override
	public Map<String, String> getProperties() {
		Map<String, String> properties = new HashMap<>();
		properties.put(TARGET, getTarget());

		if (CoreConstants.UPLOAD_DIRECT.equals(m_scanMethod)) {
			properties.put(CoreConstants.UPLOAD_DIRECT, "true");
		}

		if (m_openSourceOnly) {
			properties.put(CoreConstants.OPEN_SOURCE_ONLY, "true");
		}

		if (m_sourceCodeOnly && !CoreConstants.UPLOAD_DIRECT.equals(m_scanMethod)) {
			properties.put(CoreConstants.SOURCE_CODE_ONLY, "true");
		}

		if (m_includeSCA) {
			properties.put(CoreConstants.INCLUDE_SCA, "true");
		}

		if (m_scanSpeed != null && !m_scanSpeed.isEmpty()) {
			properties.put(SCAN_SPEED, m_scanSpeed);
		}

		if (m_rescan && m_scanId != null && !m_scanId.isEmpty()) {
			properties.put(CoreConstants.SCAN_ID, m_scanId);
		}

		return properties;
	}
}
