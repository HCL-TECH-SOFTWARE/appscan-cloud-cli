/*
 * *
 *  * @ Copyright HCL Technologies Ltd. 2023.
 *  * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 *
 */

package com.hcl.appscan.cli.constants;

import com.hcl.appscan.sdk.CoreConstants;

public interface ScannerConstants {
	
	String EMPTY					= "";					
	String ENABLE_MAIL_NOTIFICATION			= "EnableMailNotification";		
	String EXTRA_FIELD				= "ExtraField";				
	String INCLUDE_VERIFIED_DOMAINS			= "IncludeVerifiedDomains";		
	String LOGIN_USER				= "LoginUser";				
	String LOGIN_PASSWORD				= "LoginPassword";				
	String LOGIN_TYPE				= "LoginType";				
	String AUTOMATIC				= "Automatic";				
	String RECORDED					= "Manual";				
	String NONE					= "None";				
	String TRAFFIC_FILE				= "trafficFile";				
	String PRESENCE_ID				= "PresenceId";				
	String SCAN_FILE				= "ScanFile";				
	String SCAN_TYPE				= "ScanType";				
	String TEST_POLICY				= "TestPolicy";				
	String TARGET					= CoreConstants.TARGET;			
	String TEMPLATE_EXTENSION			= ".scant";				
	String TEMPLATE_EXTENSION2			= ".scan";				
	String TEMPLATE_EXTENSION3			= ".config";				
	
	String DYNAMIC_ANALYZER				= "Dynamic Analyzer";			
	String STATIC_ANALYZER				= "Static Analyzer";			

	String CUSTOM					= "Custom";				
	String PRODUCTION				= "Production";				
	String STAGING					= "Staging";				
	
	String NORMAL					= "Normal";				
	String OPTIMIZED				= "Optimized";				
	String FAST                     = "Fast";                   
	String FASTER                   = "Faster";                 
	String FASTEST                  = "Fastest";                
	String NO_OPTIMIZATION          = "NoOptimization";         
	String TEST_OPTIMIZATION_LEVEL  = "TestOptimizationLevel";
	String FULLY_AUTOMATIC = "FullyAutomatic";

	String CLIENT_TYPE = "ClientType";

}
