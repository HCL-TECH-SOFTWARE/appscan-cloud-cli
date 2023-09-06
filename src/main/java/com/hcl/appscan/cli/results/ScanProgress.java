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
