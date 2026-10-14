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

	private boolean m_sourceCodeOnly;
	private boolean m_includeSoftwareCompositionAnalysis;
	private String m_scanMethod;
	private String m_scanId;

	public StaticAnalyzer(String target) {
		this(target, false, false, true, CoreConstants.CREATE_IRX, null);
	}

	public StaticAnalyzer(String target, boolean hasOptions, boolean sourceCodeOnly,
						  boolean includeSoftwareCompositionAnalysis,
						  String scanMethod, String scanId) {
		super(target, hasOptions);
		m_sourceCodeOnly = sourceCodeOnly;
		m_includeSoftwareCompositionAnalysis = includeSoftwareCompositionAnalysis;
		m_scanMethod = scanMethod;
		m_scanId = scanId;
	}

	public boolean isSourceCodeOnly() {
		return m_sourceCodeOnly;
	}

	public void setSourceCodeOnly(boolean sourceCodeOnly) {
		m_sourceCodeOnly = sourceCodeOnly;
	}

	public boolean isIncludeSoftwareCompositionAnalysis() {
		return m_includeSoftwareCompositionAnalysis;
	}

	public void setIncludeSoftwareCompositionAnalysis(boolean includeSoftwareCompositionAnalysis) {
		m_includeSoftwareCompositionAnalysis = includeSoftwareCompositionAnalysis;
	}

	public String getScanMethod() {
		return m_scanMethod;
	}

	public void setScanMethod(String scanMethod) {
		m_scanMethod = scanMethod;
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

		if (m_sourceCodeOnly && !CoreConstants.UPLOAD_DIRECT.equals(m_scanMethod)) {
			properties.put(CoreConstants.SOURCE_CODE_ONLY, "true");
		}

		if (m_includeSoftwareCompositionAnalysis) {
			properties.put(CoreConstants.INCLUDE_SCA, "true");
		}

		if (m_scanId != null && !m_scanId.isEmpty()) {
			properties.put(CoreConstants.SCAN_ID, m_scanId);
		}

		return properties;
	}
}
