/*
 * *
 *  * @ Copyright HCL Technologies Ltd. 2023.
 *  * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 *
 */

package com.hcl.appscan.cli.results;

import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.logging.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

public class ScanProgress implements IProgress, Serializable {

	private static final long serialVersionUID = 1L;

	private static final Logger logger = LoggerFactory.getLogger(ScanProgress.class);

	@Override
	public void setStatus(Message status) {
		logger.info(status.getSeverityString() + status.getText());
	}

	@Override
	public void setStatus(Throwable e) {
		logger.error(Message.ERROR_SEVERITY + e.getLocalizedMessage());
	}

	@Override
	public void setStatus(Message status, Throwable e) {
		logger.info(status.getSeverityString() + status.getText() + "\n" + e.getLocalizedMessage());
	}
}
