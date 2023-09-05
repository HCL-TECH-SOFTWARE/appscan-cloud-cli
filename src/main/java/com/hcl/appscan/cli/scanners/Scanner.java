/*
 * *
 *  * @ Copyright HCL Technologies Ltd. 2023.
 *  * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 *
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
