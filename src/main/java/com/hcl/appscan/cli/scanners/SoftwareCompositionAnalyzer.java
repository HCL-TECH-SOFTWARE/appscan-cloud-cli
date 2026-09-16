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

public class SoftwareCompositionAnalyzer extends Scanner {

	private static final long serialVersionUID = 1L;

	private boolean m_rescan;
	private String m_scanId;

	public SoftwareCompositionAnalyzer(String target) {
		this(target, false, false, null);
	}

	public SoftwareCompositionAnalyzer(String target, boolean hasOptions, boolean rescan, String scanId) {
		super(target, hasOptions);
		m_rescan = rescan;
		m_scanId = scanId;
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
		return SOFTWARE_COMPOSITION_ANALYZER;
	}

	@Override
	public Map<String, String> getProperties() {
		Map<String, String> properties = new HashMap<>();
		properties.put(TARGET, getTarget());

		if (m_rescan && m_scanId != null && !m_scanId.isEmpty()) {
			properties.put(CoreConstants.SCAN_ID, m_scanId);
		}

		return properties;
	}
}
