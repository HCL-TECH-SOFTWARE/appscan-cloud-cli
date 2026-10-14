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
import com.hcl.appscan.cli.scanners.StaticAnalyzer;
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
import com.hcl.appscan.sdk.scanners.sast.SASTScanFactory;
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

enum ScanMethod { createIRX, uploadDirect }

@Command(name = "invokesastscan", sortOptions = false, mixinStandardHelpOptions = true, version = "1.0",
        description = "This command configures and triggers a Static Application Security Testing (SAST) scan on AppScan on Cloud or AppScan 360. It generates an IRX file or uploads source code directly, submits the scan, and retrieves the results including vulnerabilities, reports, and scan logs.",
        optionListHeading = "%n@|bold,underline Options|@:%n", descriptionHeading = "%n@|bold,underline Description|@:%n%n",
        subcommands = {HelpCommand.class})
public class InvokeStaticScan implements Callable<Integer> {

    private static final Logger logger = LoggerFactory.getLogger(InvokeStaticScan.class);
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
    @Option(names = {"--scanMethod"}, defaultValue = "createIRX", description = "[Optional] The scan method to use. 'createIRX' generates an IRX file locally using SAClient. 'uploadDirect' uploads source files directly. Valid values : ${COMPLETION-CANDIDATES}", required = false, showDefaultValue = Visibility.ALWAYS, order = 6)
    private ScanMethod scanMethod;
    @Option(names = {"--openSourceOnly"}, defaultValue = "false", paramLabel = "BOOLEAN", description = "[Optional] When set to true, only open source analysis (SCA) is performed.", required = false, showDefaultValue = Visibility.ALWAYS, order = 7)
    private boolean openSourceOnly;
    @Option(names = {"--staticAnalysisOnly"}, defaultValue = "false", paramLabel = "BOOLEAN", description = "[Optional] Only run static analysis. Do not run SCA (Software Composition Analysis).", required = false, showDefaultValue = Visibility.ALWAYS, order = 8)
    private boolean staticAnalysisOnly;
    @Option(names = {"--sourceCodeOnly"}, defaultValue = "true", paramLabel = "BOOLEAN", description = "[Optional] When set to true, only source code is analyzed (no binary analysis). Not applicable with uploadDirect scan method.", required = false, showDefaultValue = Visibility.ALWAYS, order = 9)
    private boolean sourceCodeOnly;
    @Option(names = {"--reportFormat"}, defaultValue = "html", description = "[Optional] Specify the format for the scan result report. Valid values : ${COMPLETION-CANDIDATES}.", required = false, showDefaultValue = Visibility.ALWAYS, order = 10)
    private ReportFormat reportFormat;
    private Boolean waitForResults;
    private Boolean failBuildNonCompliance;
    @Option(names = {"--sastScanId"}, description = "[Optional] The ID of an existing SAST scan to use for running a rescan.", required = false, order = 13)
    private String sastScanId;
    @Option(names = {"--scaScanId"}, description = "[Optional] The ID of an existing SCA scan to use for running a rescan.", required = false, order = 14)
    private String scaScanId;
    @Option(names = {"--serviceUrl"}, description = "[Optional] AppScan Service URL", required = false, order = 15)
    private String serviceUrl;
    private Boolean acceptssl;

    @Option(names = {"--target"}, description = "[Required] Path to the source code directory, IRX file, or zip file to scan.", required = true, order = 5)
    public void setTarget(String path) {
        File targetFile = new File(path);
        if (!targetFile.exists()) {
            throw new ParameterException(spec.commandLine(),
                    String.format(messageBundle.getString("error.invalid.target.path"), path));
        }
        target = targetFile.getAbsolutePath();
    }

    @Option(names = {"--acceptssl"}, defaultValue = "false", paramLabel = "BOOLEAN", description = "[Optional] Ignore untrusted certificates when connecting to AppScan 360. Not applicable to AppScan on Cloud.", required = false, showDefaultValue = Visibility.ALWAYS, order = 16)
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

    @Option(names = {"--failBuildNonCompliance"}, defaultValue = "false", paramLabel = "BOOLEAN", description = "[Optional] Fail the job if one or more issues are found which are non compliant with respect to the selected application's policies.", required = false, showDefaultValue = Visibility.ALWAYS, order = 13)
    public void setFailBuildNonCompliance(String value) {
        boolean invalid = !"true".equalsIgnoreCase(value) && !"false".equalsIgnoreCase(value);
        if (invalid) {
            throw new ParameterException(spec.commandLine(),
                    String.format(messageBundle.getString("error.invalid.failBuildNonCompliance"), value));
        }
        failBuildNonCompliance = Boolean.parseBoolean(value);
    }

    @Option(names = {"--waitForResults"}, defaultValue = "false", paramLabel = "BOOLEAN", description = "[Optional] Suspend the job until the security analysis results are available.", required = false, showDefaultValue = Visibility.ALWAYS, order = 11)
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
        return invokeStaticScan();
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
            List<ScanResults> results = runScanAndGetResults();
            if (exceedsThresholds(results, totalissuesgt, criticalissuesgt, highissuesgt, medissuesgt, lowissuesgt)) {
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

    private boolean exceedsThresholds(List<ScanResults> results, int totalissuesgt, int criticalissuesgt,
                                      int highissuesgt, int medissuesgt, int lowissuesgt) {
        long totalFindings = results.stream().mapToLong(ScanResults::getTotalFindings).sum();
        long criticalFindings = results.stream().mapToLong(ScanResults::getCriticalCount).sum();
        long highFindings = results.stream().mapToLong(ScanResults::getHighCount).sum();
        long mediumFindings = results.stream().mapToLong(ScanResults::getMediumCount).sum();
        long lowFindings = results.stream().mapToLong(ScanResults::getLowCount).sum();
        return totalFindings > totalissuesgt || criticalFindings > criticalissuesgt ||
                highFindings > highissuesgt || mediumFindings > medissuesgt || lowFindings > lowissuesgt;
    }

    private int invokeStaticScan() throws Exception {
        if (!waitForResults && failBuildNonCompliance) {
            logger.error(messageBundle.getString("error.invalid.waitforresults.withfailBuildNonCompliance"));
            return 2;
        }
        try {
            List<ScanResults> results = runScanAndGetResults();
            if (failBuildNonCompliance && results.stream().anyMatch(result -> result.getTotalFindings() > 0)) {
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

    private List<ScanResults> runScanAndGetResults() throws Exception {
        validateScanOptions();

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

        if (!openSourceOnly && !ServiceUtil.hasSastEntitlement(authHandler)) {
            throw new ParameterException(spec.commandLine(),
                    messageBundle.getString("error.sast.entitlement"));
        }

        boolean includeSoftwareCompositionAnalysis = !staticAnalysisOnly && !openSourceOnly;
        if ((openSourceOnly || includeSoftwareCompositionAnalysis) && !ServiceUtil.hasScaEntitlement(authHandler)) {
            if (openSourceOnly || hasScaScanId()) {
                throw new ParameterException(spec.commandLine(),
                        messageBundle.getString("error.sca.entitlement"));
            }
            logger.warn(messageBundle.getString("warning.sca.no.entitlement"));
            includeSoftwareCompositionAnalysis = false;
        }

        if (isCombinedScan() && (hasSastScanId() || hasScaScanId()) && includeSoftwareCompositionAnalysis) {
            List<ScanResults> results = new ArrayList<>();
            results.addAll(runSubmittedScan(getStaticScan(authHandler, false, "SAST"), authHandler));
            results.addAll(runSubmittedScan(getScaScan(authHandler, "SCA"), authHandler));
            return results;
        }

        if (openSourceOnly) {
            return runSubmittedScan(getScaScan(authHandler, null), authHandler);
        }

        return runSubmittedScan(getStaticScan(authHandler, includeSoftwareCompositionAnalysis, null), authHandler);
    }

    private void validateScanOptions() {
        if (staticAnalysisOnly && openSourceOnly) {
            throw new ParameterException(spec.commandLine(),
                    messageBundle.getString("error.staticAnalysisOnly.openSourceOnly"));
        }

        if (staticAnalysisOnly && hasScaScanId()) {
            throw new ParameterException(spec.commandLine(),
                    messageBundle.getString("error.scaScanId.staticAnalysisOnly"));
        }

        if (openSourceOnly && hasSastScanId()) {
            throw new ParameterException(spec.commandLine(),
                    messageBundle.getString("error.sastScanId.openSourceOnly"));
        }

        if (!openSourceOnly && sourceCodeOnly && ScanMethod.uploadDirect.equals(scanMethod)) {
            throw new ParameterException(spec.commandLine(),
                    messageBundle.getString("error.sourceCodeOnly.uploadDirect"));
        }
    }

    private boolean isCombinedScan() {
        return !staticAnalysisOnly && !openSourceOnly;
    }

    private boolean hasSastScanId() {
        return sastScanId != null && !sastScanId.isBlank();
    }

    private boolean hasScaScanId() {
        return scaScanId != null && !scaScanId.isBlank();
    }

    private List<ScanResults> runSubmittedScan(IScan scan, CloudAuthenticationHandler authHandler) throws Exception {
        Optional<ScanResults> results = Optional.empty();
        CloudResultsProvider resultsProvider = null;
        try {
            scan.run();
            if (!waitForResults) {
                return Collections.emptyList();
            }
            IProgress progress = new ScanProgress();
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
        return results.map(Collections::singletonList).orElseGet(Collections::emptyList);
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

    private IScan getStaticScan(CloudAuthenticationHandler authHandler, boolean includeSoftwareCompositionAnalysis, String scanNameSuffix) throws Exception {
        IScanFactory factory = new SASTScanFactory();
        StaticAnalyzer scanner = getStaticAnalyzer(includeSoftwareCompositionAnalysis);
        Map<String, String> properties = getScanProperties(scanner, authHandler, "SAST", scanNameSuffix);
        return factory.create(properties, new ScanProgress(), authHandler);
    }

    private IScan getScaScan(CloudAuthenticationHandler authHandler, String scanNameSuffix) throws Exception {
        IScanFactory factory = new SCAScanFactory();
        SoftwareCompositionAnalyzer scanner = getSoftwareCompositionAnalyzer();
        Map<String, String> properties = getScanProperties(scanner, authHandler, "SCA", scanNameSuffix);
        return factory.create(properties, new ScanProgress(), authHandler);
    }

    private Map<String, String> getScanProperties(Scanner scanner, CloudAuthenticationHandler authHandler, String defaultScanNamePrefix, String scanNameSuffix) {
        Map<String, String> properties = scanner.getProperties();
        properties.put(CoreConstants.SCANNER_TYPE, scanner.getType());
        properties.put(CoreConstants.APP_ID, appId);
        String timestamp = SystemUtil.getTimeStamp();
        String configuredScanName;
        if (null == scanName || "".equals(scanName)) {
            configuredScanName = defaultScanNamePrefix + "_" + timestamp + "_" + target;
        } else {
            configuredScanName = scanName + (scanNameSuffix == null ? "" : "_" + scanNameSuffix) + "_" + timestamp;
        }
        properties.put(CoreConstants.SCAN_NAME, configuredScanName);
        properties.put(CoreConstants.SERVER_URL, authHandler.getServer());
        properties.put(CoreConstants.ACCEPT_INVALID_CERTS, Boolean.toString(authHandler.getacceptInvalidCerts()));
        properties.put(CLIENT_TYPE, LoginUtility.getClientType());
        return properties;
    }

    private StaticAnalyzer getStaticAnalyzer(boolean includeSoftwareCompositionAnalysis) {
        StaticAnalyzer scanner = new StaticAnalyzer(target);
        scanner.setSourceCodeOnly(sourceCodeOnly);
        scanner.setIncludeSoftwareCompositionAnalysis(includeSoftwareCompositionAnalysis);
        scanner.setScanMethod(scanMethod.name());
        if (hasSastScanId()) {
            scanner.setScanId(sastScanId);
        }
        return scanner;
    }

    private SoftwareCompositionAnalyzer getSoftwareCompositionAnalyzer() {
        SoftwareCompositionAnalyzer scanner = new SoftwareCompositionAnalyzer(target);
        scanner.setRescan(hasScaScanId());
        if (hasScaScanId()) {
            scanner.setScanId(scaScanId);
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
        logger.info(messageBundle.getString("info.sast.scan.progress"), scan.getName(), scan.getScanId());
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
            logger.info(messageBundle.getString("info.sast.scan.completed"), m_scanStatus);
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
        logger.info(messageBundle.getString("sast.scan.summary.format"), appId,
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
