/*
 * *
 *  * @ Copyright HCL Technologies Ltd. 2023.
 *  * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 *
 */

package com.hcl.appscan.cli.results;


import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.results.IResultsProvider;

public class ScanResults  {

	private static final String REPORT_SUFFIX = "_report"; 
	protected static final String URL = "https://cloud.appscan.com";
	private final IResultsProvider m_provider;
	private final String m_name;
	private final String m_status;
	private final String m_scanServerUrl;

	private final int m_totalFindings;
	private final int m_criticalCount;
	private final int m_highCount;
	private final int m_mediumCount;
	private final int m_lowCount;
	private final int m_infoCount;
	

	public ScanResults(IResultsProvider provider, String name, String status,
                       int totalFindings, int criticalCount, int highCount, int mediumCount, int lowCount, int infoCount, String scanServerUrl) {

		m_provider = provider;
		m_name = name;
		m_status = status;
		m_totalFindings = totalFindings;
                m_criticalCount = criticalCount;
		m_highCount = highCount;
		m_mediumCount = mediumCount;
		m_lowCount = lowCount;
		m_infoCount = infoCount;

		m_scanServerUrl = scanServerUrl;
                //getReport();
	}
	

	public String getUrlName() {
		return getReportName();
	}
	

	
	public String getName() {
		return m_name;
	}
	
	public String getScanType() {
		return m_provider.getType();
	}
	
	public int getHighCount() {
		return m_highCount;
	}
	
	public int getMediumCount() {
		return m_mediumCount;
	}
	
	public int getLowCount() {
		return m_lowCount;
	}

	public int getCriticalCount(){
                return m_criticalCount;
        }
	public int getInfoCount() {
		return m_infoCount;
	}
	
	public int getTotalFindings() {
		return m_totalFindings;
	}
	
	public boolean getHasResults() {
		return !m_status.equalsIgnoreCase(CoreConstants.FAILED);
	}
	
	public boolean getFailed() {
		String status = m_status == null ? m_provider.getStatus() : m_status;
		return status.equalsIgnoreCase(CoreConstants.FAILED);
	}

	public String getScanServerUrl()  {
		return m_scanServerUrl;
	}


	private String getReportName() {
		String name = (getScanType() + getName()).replaceAll(" ", "");  //$NON-NLS-2$
		return name + REPORT_SUFFIX + "." + m_provider.getResultsFormat().toLowerCase(); 
	}


	@Override
	public String toString() {
		return "ScanResults{" +
				"m_provider=" + m_provider +
				", m_name='" + m_name + '\'' +
				", m_status='" + m_status + '\'' +
				", m_scanServerUrl='" + m_scanServerUrl + '\'' +
				", m_totalFindings=" + m_totalFindings +
				", m_criticalCount=" + m_criticalCount +
				", m_highCount=" + m_highCount +
				", m_mediumCount=" + m_mediumCount +
				", m_lowCount=" + m_lowCount +
				", m_infoCount=" + m_infoCount +
				'}';
	}
}
