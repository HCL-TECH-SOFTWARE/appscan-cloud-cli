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


import com.hcl.appscan.cli.constants.ScannerConstants;

import java.io.Serializable;
import java.util.Map;


public abstract class Scanner  implements ScannerConstants, Serializable {

	private static final long serialVersionUID = 1L;

	private final String m_target;
	private final boolean m_hasOptions;
	
	public Scanner(String target, boolean hasOptions) {
		m_target = target;
		m_hasOptions = hasOptions;
	}
	
	public boolean getHasOptions() {
		return m_hasOptions;
	}
	
	public String getTarget() {
		return m_target;
	}
	
	public abstract Map<String, String> getProperties();
	
	public abstract String getType();
	

}
