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

package com.hcl.appscan.cli.handlers;

import com.hcl.appscan.cli.auth.CloudAuthenticationHandler;
import com.hcl.appscan.cli.auth.LoginUtility;
import com.hcl.appscan.cli.constants.ScannerConstants;
import com.hcl.appscan.cli.exception.AbortException;
import com.hcl.appscan.cli.results.ScanProgress;
import com.hcl.appscan.cli.results.ScanResults;
import com.hcl.appscan.cli.scanners.Scanner;
import com.hcl.appscan.cli.scanners.SoftwareCompositionAnalyzer;
import com.hcl.appscan.cli.scanners.ValidationUtil;
import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.results.CloudResultsProvider;
import com.hcl.appscan.sdk.results.IResultsProvider;
import com.hcl.appscan.sdk.results.NonCompliantIssuesResultProvider;
import com.hcl.appscan.sdk.scan.IScan;
import com.hcl.appscan.sdk.scan.IScanFactory;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;
import com.hcl.appscan.sdk.scanners.ScanConstants;
import com.hcl.appscan.sdk.scanners.sca.SCAScanFactory;
import com.hcl.appscan.sdk.utils.ServiceUtil;
import com.hcl.appscan.sdk.utils.SystemUtil;
import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;

import static com.hcl.appscan.cli.constants.CLIConstants.*;
import static com.hcl.appscan.cli.constants.ScannerConstants.*;
import static java.io.File.separator;
import static picocli.CommandLine.*;
import static picocli.CommandLine.Help.*;

@Command(name = "invokescascan", sortOptions = false, mixinStandardHelpOptions = true, version = "1.0",
        description = "This command configures and triggers a Software Composition Analysis (SCA) scan on AppScan on Cloud or AppScan 360. It analyzes open source and third-party components in your source code for known vulnerabilities.",
        optionListHeading = "%n@|bold,underline Options|@:%n", descriptionHeading = "%n@|bold,underline Description|@:%n%n",
        subcommands = {HelpCommand.class})
public class InvokeSCAScan implements Callable<Integer> {

    private static final Logger logger = LoggerFactory.getLogger(InvokeSCAScan.class);
    ResourceBundle messageBundle = ResourceBundle.getBundle("messages");
    @Spec
    Model.CommandSpec spec;

    @Option(names = {"--key"}, description = "[Required] AppScan on Cloud or AppScan 360 API Key", required = true, order = 1)
    private String key;
    @Option(names = {"--secret"}, description = "[Required] AppScan on Cloud or AppScan 360 API Secret", required = true, order = 2)
    private String secret;
    @Option(names = {"--appId"}, description = "[Required] The HCL AppScan on Cloud or AppScan 360 application that this scan will be associated with", required = true, order = 3)
    private String appId;
    @Option(names = {"--scanName"}, description = "[Required] Specify a name to use for the scan.", required = true, order = 4)
    private String scanName;
    private String target;
    @Option(names = {"--reportFormat"}, defaultValue = "html", description = "[Optional] Specify the format for the scan result report. Valid values : ${COMPLETION-CANDIDATES}.", required = false, showDefaultValue = Visibility.ALWAYS, order = 6)
    private ReportFormat reportFormat;
    private Boolean waitForResults;
    private Boolean failBuildNonCompliance;
    @Option(names = {"--rescan"}, defaultValue = "false", paramLabel = "BOOLEAN", description = "[Optional] When set to true, performs a rescan of an existing scan specified by --scanId.", required = false, showDefaultValue = Visibility.ALWAYS, order = 9)
    private boolean rescan;
    @Option(names = {"--scanId"}, description = "[Optional] The scan ID to rescan. Required when --rescan is set to true.", required = false, order = 10)
    private String scanId;
    @Option(names = {"--serviceUrl"}, description = "[Optional] AppScan Service URL", required = false, order = 11)
    private String serviceUrl;
    private Boolean acceptssl;

    @Option(names = {"--target"}, description = "[Required] Path to the source code directory to scan.", required = true, order = 5)
    public void setTarget(String path) {
        File targetFile = new File(path);
        if (!targetFile.exists()) {
            throw new ParameterException(spec.commandLine(),
                    String.format(messageBundle.getString("error.invalid.target.path"), path));
        }
        target = targetFile.getAbsolutePath();
    }

    @Option(names = {"--acceptssl"}, defaultValue = "false", paramLabel = "BOOLEAN", description = "[Optional] Ignore untrusted certificates when connecting to AppScan 360. Not applicable to AppScan on Cloud.", required = false, showDefaultValue = Visibility.ALWAYS, order = 12)
    public void setAcceptssl(String value) {
        if (null != key && !key.startsWith("local_") && (!value.isBlank() && !"false".equalsIgnoreCase(value))) {
            logger.warn(messageBundle.getString("error.acceptssl.without.a360"));
        }
        if (null != key && key.startsWith("local_")) {
            boolean invalid = !"true".equalsIgnoreCase(value) && !"false".equalsIgnoreCase(value);
            if (invalid) {
                throw new ParameterException(spec.commandLine(),
                        String.format(messageBundle.getString("error.invalid.acceptssl"), value));
            } else if ("true".equalsIgnoreCase(value) && serviceUrl == null) {
                throw new ParameterException(spec.commandLine(),
                        String.format(messageBundle.getString("error.acceptssl.without.serviceurl")));
            }
            acceptssl = Boolean.parseBoolean(value);
        }
    }

    @Option(names = {"--failBuildNonCompliance"}, defaultValue = "false", paramLabel = "BOOLEAN", description = "[Optional] Fail the job if one or more issues are found which are non compliant with respect to the selected application's policies.", required = false, showDefaultValue = Visibility.ALWAYS, order = 8)
    public void setFailBuildNonCompliance(String value) {
        boolean invalid = !"true".equalsIgnoreCase(value) && !"false".equalsIgnoreCase(value);
        if (invalid) {
            throw new ParameterException(spec.commandLine(),
                    String.format(messageBundle.getString("error.invalid.failBuildNonCompliance"), value));
        }
        failBuildNonCompliance = Boolean.parseBoolean(value);
    }

    @Option(names = {"--waitForResults"}, defaultValue = "true", paramLabel = "BOOLEAN", description = "[Optional] Suspend the job until the security analysis results are available.", required = false, showDefaultValue = Visibility.ALWAYS, order = 7)
    public void setWaitForResults(String value) {
        boolean invalid = !"true".equalsIgnoreCase(value) && !"false".equalsIgnoreCase(value);
        if (invalid) {
            throw new ParameterException(spec.commandLine(),
                    String.format(messageBundle.getString("error.invalid.waitForResults"), value));
        }
        waitForResults = Boolean.parseBoolean(value);
    }

    @Override
    public Integer call() throws Exception {
        return invokeSCAScan();
    }

    @Command(name = "failbuildif", description = "[Optional] A list of conditions that will fail the build. These conditions are logically \"OR\"'d together.")
    int failbuildif(@Option(names = {"--totalissuesgt", "-ti"}, description = "Fail build if total issues greater than", defaultValue = Integer.MAX_VALUE + "") int totalissuesgt,
                    @Option(names = {"--highissuesgt", "-hi"}, description = "Fail build if high sev issues greater than", defaultValue = Integer.MAX_VALUE + "") int highissuesgt,
                    @Option(names = {"--medissuesgt", "-mi"}, description = "Fail build if medium sev issues greater than", defaultValue = Integer.MAX_VALUE + "") int medissuesgt,
                    @Option(names = {"--lowissuesgt", "-li"}, description = "Fail build if low sev issues greater than", defaultValue = Integer.MAX_VALUE + "") int lowissuesgt,
                    @Option(names = {"--criticalissuesgt", "-ci"}, description = "Fail build if critical sev issues greater than", defaultValue = Integer.MAX_VALUE + "") int criticalissuesgt) {

        if (totalissuesgt == Integer.MAX_VALUE && highissuesgt == Integer.MAX_VALUE && medissuesgt == Integer.MAX_VALUE && lowissuesgt == Integer.MAX_VALUE && criticalissuesgt == Integer.MAX_VALUE) {
            throw new ParameterException(spec.commandLine(),
                    String.format(messageBundle.getString("error.failbuildif.nothresholdspecified")));
        }
        StringBuilder thresholdErrMsg = new StringBuilder();
        if (totalissuesgt < 0) thresholdErrMsg.append(messageBundle.getString("error.invalid.totalissuesgt"));
        if (highissuesgt < 0) thresholdErrMsg.append(messageBundle.getString("error.invalid.highissuesgt"));
        if (medissuesgt < 0) thresholdErrMsg.append(messageBundle.getString("error.invalid.medissuesgt"));
        if (lowissuesgt < 0) thresholdErrMsg.append(messageBundle.getString("error.invalid.lowissuesgt"));
        if (criticalissuesgt < 0) thresholdErrMsg.append(messageBundle.getString("error.invalid.criticalissuesgt"));
        if (totalissuesgt < 0 || highissuesgt < 0 || medissuesgt < 0 || lowissuesgt < 0 || criticalissuesgt < 0) {
            throw new ParameterException(spec.commandLine(), thresholdErrMsg.toString());
        }
        if (!waitForResults) {
            throw new ParameterException(spec.commandLine(),
                    String.format(messageBundle.getString("error.invalid.waitforresults.withfailbuildif")));
        }
        if (failBuildNonCompliance) {
            throw new ParameterException(spec.commandLine(),
                    String.format(messageBundle.getString("error.invalid.failbuildif.withfailBuildNonCompliance")));
        }

        try {
            Optional<ScanResults> results = runScanAndGetResults();
            if (results.isPresent() && (results.get().getTotalFindings() > totalissuesgt || results.get().getCriticalCount() > criticalissuesgt ||
                    results.get().getHighCount() > highissuesgt || results.get().getMediumCount() > medissuesgt || results.get().getLowCount() > lowissuesgt)) {
                logger.error(messageBundle.getString("error.threshold.exceeded"));
                return 10;
            } else {
                logger.info(messageBundle.getString("info.within.threshold"));
                return 0;
            }
        } catch (Exception e) {
            return 10;
        }
    }

    private int invokeSCAScan() throws Exception {
        if (!waitForResults && failBuildNonCompliance) {
            logger.error(messageBundle.getString("error.invalid.waitforresults.withfailBuildNonCompliance"));
            return 2;
        }
        try {
            Optional<ScanResults> results = runScanAndGetResults();
            if (failBuildNonCompliance && results.isPresent() && results.get().getTotalFindings() > 0) {
                logger.error(messageBundle.getString("error.noncomplaint.issues"));
                return 12;
            }
        } catch (ParameterException pe) {
            throw pe;
        } catch (Exception e) {
            return 10;
        }
        return 0;
    }

    private Optional<ScanResults> runScanAndGetResults() throws Exception {
        CloudAuthenticationHandler authHandler;
        if (null != serviceUrl && key.startsWith("local_")) {
            if (serviceUrl.endsWith("/")) {
                serviceUrl = serviceUrl.substring(0, serviceUrl.length() - 1);
            }
            boolean isValidURL = ValidationUtil.checkASoCConnectivity(serviceUrl, acceptssl);
            if (!isValidURL) {
                throw new ParameterException(spec.commandLine(),
                        String.format(messageBundle.getString("error.unreachable.serviceurl")));
            }
            authHandler = new CloudAuthenticationHandler(serviceUrl, acceptssl);
        } else {
            authHandler = new CloudAuthenticationHandler();
        }

        try {
            boolean isAuthenticated = authHandler.updateCredentials(key, secret);
            if (!isAuthenticated) {
                throw new ParameterException(spec.commandLine(),
                        String.format(messageBundle.getString("error.invalid.credentials")));
            }
        } catch (ParameterException pe) {
            throw pe;
        } catch (Exception e) {
            throw new ParameterException(spec.commandLine(),
                    String.format(messageBundle.getString("error.invalid.credentials")));
        }

        if (!ServiceUtil.hasScaEntitlement(authHandler)) {
            throw new ParameterException(spec.commandLine(),
                    messageBundle.getString("error.sca.entitlement"));
        }

        if (rescan && (scanId == null || scanId.isEmpty())) {
            throw new ParameterException(spec.commandLine(),
                    messageBundle.getString("error.rescan.requires.scanId"));
        }

        Optional<ScanResults> results = Optional.empty();
        IScan scan = null;
        CloudResultsProvider resultsProvider = null;
        try {
            IProgress progress = new ScanProgress();
            scan = getScan(authHandler, progress);
            scan.run();
            if (!waitForResults) {
                return results;
            }
            resultsProvider = new NonCompliantIssuesResultProvider(scan.getScanId(), scan.getType(), scan.getServiceProvider(), progress);
            results = getScanResults(scan, progress, authHandler, resultsProvider);
            processScanResults(results, resultsProvider, scan);
        } catch (ParameterException pe) {
            throw pe;
        } catch (Exception e) {
            logger.error(e.getMessage());
            throw e;
        } finally {
            if (null != scan && null != resultsProvider)
                getScanLogs(scan, resultsProvider);
        }
        return results;
    }

    private void processScanResults(Optional<ScanResults> results, IResultsProvider resultsProvider, IScan scan) throws Exception {
        if (results.isPresent()) {
            logScanResults(scan, results.get());
            logger.info("Downloading Scan Report. Please wait...");
            resultsProvider.setReportFormat(reportFormat.name());
            ExecutorService executor = Executors.newSingleThreadExecutor();
            Callable<String> downloadReportTask = () -> {
                File report = getReport(resultsProvider, results.get());
                String reportPath = report.getAbsolutePath();
                return "Report downloaded successfully. Download location - " + reportPath;
            };
            try {
                Future<String> future = executor.submit(downloadReportTask);
                String reportDownloadResult = future.get(90, TimeUnit.SECONDS);
                logger.info(reportDownloadResult);
            } catch (TimeoutException e) {
                logger.error("Unable to download the report. Operation timed out!");
            } catch (Exception e) {
                logger.error("Caught Exception while downloading the report : Error - " + e.getMessage());
            } finally {
                executor.shutdown();
            }
        } else {
            logger.error(messageBundle.getString("error.invalid.scanresult"));
            throw new AbortException(com.hcl.appscan.sdk.Messages.getMessage(ScanConstants.SCAN_FAILED, (" Scan Id: " + scan.getScanId() +
                    ", Scan Name: " + scan.getName())));
        }
    }

    private IScan getScan(CloudAuthenticationHandler authHandler, IProgress progress) throws Exception {
        IScanFactory factory = new SCAScanFactory();
        SoftwareCompositionAnalyzer scanner = getSoftwareCompositionAnalyzer();
        Map<String, String> properties = getScanProperties(scanner, authHandler);
        return factory.create(properties, progress, authHandler);
    }

    private Map<String, String> getScanProperties(Scanner scanner, CloudAuthenticationHandler authHandler) {
        Map<String, String> properties = scanner.getProperties();
        properties.put(CoreConstants.SCANNER_TYPE, scanner.getType());
        properties.put(CoreConstants.APP_ID, appId);
        if (null == scanName || "".equals(scanName)) {
            scanName = "SCA_" + SystemUtil.getTimeStamp() + "_" + target;
        } else {
            scanName = scanName + "_" + SystemUtil.getTimeStamp();
        }
        properties.put(CoreConstants.SCAN_NAME, scanName);
        properties.put(CoreConstants.SERVER_URL, authHandler.getServer());
        properties.put(CoreConstants.ACCEPT_INVALID_CERTS, Boolean.toString(authHandler.getacceptInvalidCerts()));
        properties.put(CLIENT_TYPE, LoginUtility.getClientType());
        return properties;
    }

    private SoftwareCompositionAnalyzer getSoftwareCompositionAnalyzer() {
        SoftwareCompositionAnalyzer scanner = new SoftwareCompositionAnalyzer(target);
        scanner.setRescan(rescan);
        if (scanId != null) {
            scanner.setScanId(scanId);
        }
        return scanner;
    }

    public File getReport(IResultsProvider provider, ScanResults results) throws IOException {
        String cwd = Path.of("").toAbsolutePath().toString();
        String baseDir = cwd + separator + messageBundle.getString("report.download.location");
        File report = new File(baseDir, getReportName(provider, results));
        if (report.getCanonicalPath().startsWith(baseDir) && !report.isFile()) {
            provider.getResultsFile(report, null);
            return report;
        } else {
            return null;
        }
    }

    private String getReportName(IResultsProvider provider, ScanResults results) {
        String name = (provider.getType() + results.getName());
        String sanitizedName = sanitizeFileName(name);
        return sanitizedName + REPORT_SUFFIX + "." + provider.getResultsFormat().toLowerCase();
    }

    public static String sanitizeFileName(String input) {
        String regex = "[^A-Za-z0-9_-]";
        return input.replaceAll(regex, "");
    }

    private Optional<ScanResults> getScanResults(IScan scan, IProgress progress, CloudAuthenticationHandler authHandler, IResultsProvider provider) throws Exception {
        String m_scanStatus = provider.getStatus();
        Optional<ScanResults> results = Optional.empty();
        int requestCounter = 0;
        logger.info(messageBundle.getString("info.wait.for.scan"));
        logger.info(messageBundle.getString("info.sca.scan.progress"), scan.getName(), scan.getScanId());
        try {
            IScanServiceProvider scanServiceProvider = scan.getServiceProvider();
            while (m_scanStatus != null && (m_scanStatus.equalsIgnoreCase(CoreConstants.INQUEUE) || m_scanStatus.equalsIgnoreCase(CoreConstants.RUNNING) || m_scanStatus.equalsIgnoreCase(CoreConstants.UNKNOWN) || m_scanStatus.equalsIgnoreCase(CoreConstants.PAUSING) || m_scanStatus.equalsIgnoreCase(CoreConstants.PAUSED)) && requestCounter < 10) {
                String asocServerUrl;
                boolean isASoCServerReachable;
                if (serviceUrl != null && key.startsWith("local_")) {
                    asocServerUrl = serviceUrl;
                    isASoCServerReachable = ValidationUtil.checkASoCConnectivity(asocServerUrl, acceptssl);
                } else {
                    asocServerUrl = authHandler.getServer();
                    isASoCServerReachable = ValidationUtil.checkASoCConnectivity(asocServerUrl, false);
                }
                if (!isASoCServerReachable) {
                    m_scanStatus = CoreConstants.UNKNOWN;
                } else {
                    m_scanStatus = provider.getStatus();
                }
                if (SCAN_STATUS_READY.equalsIgnoreCase(m_scanStatus)) {
                    m_scanStatus = SCAN_STATUS_COMPLETED;
                }
                if (m_scanStatus.equalsIgnoreCase(CoreConstants.UNKNOWN)) {
                    System.out.printf("\rScan Status : %s [ Duration : %s , Requests Sent : %s ]", m_scanStatus, "-", "-");
                    requestCounter++;
                } else requestCounter = 0;

                if (!CoreConstants.FAILED.equalsIgnoreCase(m_scanStatus) && !CoreConstants.UNKNOWN.equalsIgnoreCase(m_scanStatus)) {
                    JSONObject scanSummary = scanServiceProvider.getScanDetails(scan.getScanId());
                    if (null != scanSummary) {
                        if (scanSummary.has("LatestExecution")) {
                            JSONObject latestExecution = scanSummary.getJSONObject("LatestExecution");
                            int duration = latestExecution.getInt("ExecutionDurationSec");
                            int minutes = duration / 60;
                            int remainingSeconds = duration % 60;
                            String formattedDuration = String.format("%02dm %02ds", minutes, remainingSeconds);
                            System.out.printf("\rScan Status : %s [ Duration : %s , Requests Sent : %s ]", m_scanStatus, formattedDuration, latestExecution.getString("Progress"));
                        }
                    }
                }
                Thread.sleep(30000);
            }
            System.out.println();
        } catch (Exception e) {
            throw new AbortException(messageBundle.getString("error.running.scan"));
        }

        if (CoreConstants.FAILED.equalsIgnoreCase(m_scanStatus)) {
            String message = com.hcl.appscan.sdk.Messages.getMessage(ScanConstants.SCAN_FAILED, " Scan Name: " + scan.getName());
            if (provider.getMessage() != null && provider.getMessage().trim().length() > 0) {
                message += ", " + provider.getMessage();
            }
            logger.error(messageBundle.getString("error.scan.cancelled"), scan.getName());
            throw new AbortException(com.hcl.appscan.sdk.Messages.getMessage(ScanConstants.SCAN_FAILED, (" Scan Id: " + scan.getScanId() +
                    ", Scan Name: " + scan.getName())));
        } else if (CoreConstants.UNKNOWN.equalsIgnoreCase(m_scanStatus)) {
            logger.error(messageBundle.getString("error.unexpected"));
        } else {
            logger.info(messageBundle.getString("info.sca.scan.completed"), m_scanStatus);
            String scanUrlPrefix = "";
            if (!authHandler.getServer().endsWith("/")) {
                scanUrlPrefix = authHandler.getServer() + "/";
            }
            String asocAppUrl = scanUrlPrefix + "main/myapps/" + appId + "/scans/" + scan.getScanId();
            ScanResults scanresults = new ScanResults(provider, scan.getName(), provider.getStatus(), provider.getFindingsCount(), provider.getCriticalCount(), provider.getHighCount(), provider.getMediumCount(), provider.getLowCount(), provider.getInfoCount(), asocAppUrl);
            results = Optional.of(scanresults);
        }
        return results;
    }

    private void logScanResults(IScan scan, ScanResults results) throws Exception {
        IScanServiceProvider scanServiceProvider = scan.getServiceProvider();
        JSONObject scanSummary = scanServiceProvider.getScanDetails(scan.getScanId());
        JSONObject createdBy = scanSummary.getJSONObject("CreatedBy");
        logger.info(messageBundle.getString("sca.scan.summary.format"), appId,
                scanSummary.getString("AppName"), scan.getScanId(), results.getName(),
                scanSummary.getString("CreatedAt"), createdBy.getString("UserName"),
                createdBy.getString("FirstName") + " " + createdBy.getString("LastName"),
                createdBy.getString("Email"), target,
                results.getScanServerUrl(), results.getTotalFindings(), results.getCriticalCount(),
                results.getHighCount(), results.getMediumCount(), results.getLowCount(), results.getInfoCount());
    }

    private void getScanLogs(IScan scan, CloudResultsProvider resultsProvider) throws JSONException, IOException {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        logger.info("Downloading Scan Logs. Please wait...");
        Callable<String> downloadScanLogTask = () -> {
            String cwd = Path.of("").toAbsolutePath().toString();
            String baseDir = cwd + separator + messageBundle.getString("report.download.location");
            String fileName = "ScanLog" + "_" + SystemUtil.getTimeStamp() + "." + "zip";
            File scanLogFile = new File(baseDir, fileName);
            resultsProvider.getScanLogFile(scanLogFile, scan.getScanId());
            if (scanLogFile.isFile()) {
                String scanLogFilePath = scanLogFile.getAbsolutePath();
                return "ScanLog File downloaded successfully. Download location - " + scanLogFilePath;
            } else {
                return "ScanLog File is not available for this Scan";
            }
        };
        try {
            Future<String> future = executor.submit(downloadScanLogTask);
            String scanLogDownloadStatus = future.get(90, TimeUnit.SECONDS);
            logger.info(scanLogDownloadStatus);
        } catch (TimeoutException e) {
            logger.error("Unable to download the scan log. Operation timed out!");
        } catch (Exception e) {
            logger.error("Caught Exception while downloading the scan log : Error - " + e.getMessage());
        } finally {
            executor.shutdown();
        }
    }
}
