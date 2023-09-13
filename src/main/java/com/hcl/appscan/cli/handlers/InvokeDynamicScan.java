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

package com.hcl.appscan.cli.handlers;

import com.hcl.appscan.cli.auth.CloudAuthenticationHandler;
import com.hcl.appscan.cli.constants.ScannerConstants;
import com.hcl.appscan.cli.results.ScanProgress;
import com.hcl.appscan.cli.results.ScanResults;
import com.hcl.appscan.cli.scanners.DynamicAnalyzer;
import com.hcl.appscan.cli.scanners.Scanner;
import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.logging.Message;
import com.hcl.appscan.sdk.results.IResultsProvider;
import com.hcl.appscan.sdk.results.NonCompliantIssuesResultProvider;
import com.hcl.appscan.sdk.scan.IScan;
import com.hcl.appscan.sdk.scan.IScanFactory;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;
import com.hcl.appscan.sdk.scanners.ScanConstants;
import com.hcl.appscan.sdk.scanners.dynamic.DASTScanFactory;
import com.hcl.appscan.sdk.utils.SystemUtil;
import org.apache.wink.json4j.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.*;
import java.util.concurrent.*;

import static com.hcl.appscan.cli.constants.CLIConstants.*;
import static com.hcl.appscan.cli.constants.ScannerConstants.*;
import static picocli.CommandLine.*;
import static picocli.CommandLine.Help.*;

enum ScanType { Production, Staging }
enum Optimization { Fast, Faster, Fastest, NoOptimization }
enum ReportFormat { html, pdf, csv, xml }
enum LoginType { None , Automatic , Manual }
@Command(name = "invokedynamicscan", sortOptions = false, mixinStandardHelpOptions = true, version = "1.0",
        description = "This Command is used to initiate the Dynamic Security Analysis Scan and seamlessly fetch the scan results upon the scan's completion. These results include identified issues, detailed reports, and corresponding report URLs. Additionally, the CLI can be configured with specific command line options to set failure conditions, enabling it to send a pass/fail signal to the pipeline accordingly" ,
        optionListHeading = "%n@|bold,underline Options|@:%n" , descriptionHeading = "%n@|bold,underline Description|@:%n%n",
        subcommands = {HelpCommand.class})
public class InvokeDynamicScan implements Callable<Integer> {

    private static final Logger logger = LoggerFactory.getLogger(InvokeDynamicScan.class);
    ResourceBundle messageBundle = ResourceBundle.getBundle("messages");
    @Spec
    Model.CommandSpec spec;

    @Option(names = {"--key"}, description = "[Required] Appscan on Cloud API Key", required = true , order = 1)
    private String key;
    @Option(names = {"--secret"}, description = "[Required] Appscan on Cloud API Secret", required = true , order = 2)
    private String secret;
    @Option(names = {"--appId"}, description = "[Required] The HCL AppScan on Cloud application that this scan will be associated with", required = true , order = 3)
    private String appId;
    @Option(names = {"--scanName"}, description = "[Required] Specify a name to use for the scan. This value is used to distinguish this scan and its results from others.", required = true , order = 4)
    private String scanName;
    @Option(names = {"--target"}, description = "[Required] Enter the URL from where you want the scan to start exploring the site.", required = true , order = 5)
    private String target;

    @Option(names = {"--scanType"}, defaultValue = "Production",description = "[Optional] Mention whether your site is a Staging site (under development) or a Production site (live and in use). Valid values : ${COMPLETION-CANDIDATES}", required = false , showDefaultValue = Visibility.ALWAYS , order = 6)
    private ScanType scanType;
    @Option(names = {"--optimization"}, defaultValue = "fast", description = "[Optional] You can reduce scan time by choosing a balance between speed and issue coverage. Valid values : ${COMPLETION-CANDIDATES}", required = false , showDefaultValue = Visibility.ALWAYS , order = 7)
    private Optimization optimization;
    @Option(names = {"--emailNotification"}, defaultValue = "false", description = "[Optional] Send the user an email when analysis is complete. Valid values : true , false", required = false , showDefaultValue = Visibility.ALWAYS , order = 8)
    private Boolean emailNotification;
    @Option(names = {"--reportFormat"},defaultValue = "html",  description = "[Optional] Specify format for the scan result report. Valid values : ${COMPLETION-CANDIDATES}.", required = false , showDefaultValue = Visibility.ALWAYS , order = 9)
    private ReportFormat reportFormat;
    @Option(names = {"--allowIntervention"},defaultValue = "false",  description = "[Optional] When set to true, our scan enablement team will step in if the scan fails, or if no issues are found, and try to fix the configuration. This may delay the scan result.", required = false ,showDefaultValue = Visibility.ALWAYS , order = 10)
    private Boolean allowIntervention;
    @Option(names = {"--presenceId"}, description = "[Optional] For sites not available on the internet, provide the ID of the AppScan Presence that can be used for the scan.", required = false ,order = 11)
    private String presenceId;
    @Option(names = {"--waitForResults"},defaultValue = "true",  description = "[Optional] Suspend the job until the security analysis results are available.", required = false ,showDefaultValue = Visibility.ALWAYS , order = 12)
    private Boolean waitForResults;
    @Option(names = {"--failBuildNonCompliance"},defaultValue = "false",  description = "[Optional] Fail the job if one or more issues are found which are non compliant with respect to the selected application's policies.", required = false ,showDefaultValue = Visibility.ALWAYS , order = 13)
    private Boolean failBuildNonCompliance;
    private  File scanFile;
    @Option(names = {"--loginType"},defaultValue = "None", description = "[Optional] Which Login method do you want to use? Type None if login not required. Type Automatic if you want to provide loginUser and password. Type Manual if you want to specify Login Sequence File. Valid values : ${COMPLETION-CANDIDATES} ", required = false ,showDefaultValue = Visibility.ALWAYS , order = 15)
    private  LoginType loginType;

    @Option(names = {"--loginUser"}, description = "[Optional] If your app requires login, enter valid user credentials so that Application Security on Cloud can log in to the site.", required = false , order = 16)
    private String loginUser;
    @Option(names = {"--loginPassword"}, description = "[Optional] If your app requires login, enter valid user credentials so that Application Security on Cloud can log in to the site.", required = false , order = 17)
    private String loginPassword;
    @Option(names = {"--trafficFile"},  description = "[Optional] Provide a path to the login sequence file data. Supported file type: CONFIG: AppScan Activity Recorder file.", required = false ,showDefaultValue = Visibility.ALWAYS , order = 18)
    private  String trafficFile;

    @Option(names = {"--scanFile"},  description = "[Optional] The path to a scan template file (.scan or .scant).", required = false ,showDefaultValue = Visibility.ALWAYS , order = 14)
    public void setScanFile(File file) {
        String value = file.getAbsolutePath();
        boolean invalid =  !value.trim().equals(EMPTY) && !value.endsWith(TEMPLATE_EXTENSION) && !value.endsWith(TEMPLATE_EXTENSION2) && !value.startsWith("${");
        if(!file.isFile()){
            throw new ParameterException(spec.commandLine(),
                    String.format(messageBundle.getString("error.invalid.filepath"), value));
        }
        if (invalid) {
            throw new ParameterException(spec.commandLine(),
                    String.format(messageBundle.getString("error.invalid.scanfile"), value));
        }
        scanFile = file;
    }

    @Override
    public Integer call() {
       return invokeDynamicScan();
    }
    @Command(name = "failbuildif", description = "[Optional] A list of conditions that will fail the build. These conditions are logically \"OR\"'d together, so if one of the conditions is met, the build will fail.")
    int failbuildif(@Option(names = {"--totalissuesgt", "-ti"}, description = "Fail build if total issues greater than", defaultValue = Integer.MAX_VALUE + "") int totalissuesgt, @Option(names = {"--highissuesgt", "-hi"}, description = "Fail build if high sev issues greater than", defaultValue = Integer.MAX_VALUE + "") int highissuesgt, @Option(names = {"--medissuesgt", "-mi"}, description = "Fail build if medium sev issues greater than", defaultValue = Integer.MAX_VALUE + "") int medissuesgt, @Option(names = {"--lowissuesgt", "-li"}, description = "Fail build if low sev issues greater than", defaultValue = Integer.MAX_VALUE + "") int lowissuesgt, @Option(names = {"--criticalissuesgt", "-ci"}, description = "Fail build if critical sev issues greater than", defaultValue = Integer.MAX_VALUE + "") int criticalissuesgt) {

        try{
            waitForResults = true;
            Optional<ScanResults> results = runScanAndGetResults();
            if (results.isPresent() && (results.get().getTotalFindings() > totalissuesgt || results.get().getCriticalCount() > criticalissuesgt ||
                    results.get().getHighCount() > highissuesgt || results.get().getMediumCount() > medissuesgt || results.get().getLowCount() > lowissuesgt )) {

                logger.error(messageBundle.getString("error.threshold.exceeded"));
                return 10;
            } else {
                logger.info(messageBundle.getString("info.within.threshold"));
                return 0;
            }
        }catch (Exception e){
            return 10;
        }
    }
    private int invokeDynamicScan(){
        try{
            Optional<ScanResults> results =  runScanAndGetResults();
            if(failBuildNonCompliance && results.isPresent() && results.get().getTotalFindings()>0){
                logger.error(messageBundle.getString("error.noncomplaint.issues"));
                return 12;
            }
        }catch (Exception e){
            return 2;
        }
        return 0;
    }
    private  Optional<ScanResults> runScanAndGetResults() throws Exception {

        CloudAuthenticationHandler authHandler = new CloudAuthenticationHandler();
        try {
            authHandler.updateCredentials(key, secret);
        } catch (Exception e) {
            logger.error("Error in Authentication : " + e.getMessage());
            throw e;
        }
        Optional<ScanResults> results = Optional.empty();
        try {
            IProgress progress = new ScanProgress();
            final IScan scan = getScan(authHandler, progress);
            scan.run();
            if(!waitForResults){
                return results;
            }
            IResultsProvider resultsProvider = new NonCompliantIssuesResultProvider(scan.getScanId(), scan.getType(), scan.getServiceProvider(), progress);
            results = getScanResults(scan, progress, authHandler, resultsProvider);
            if (results.isPresent()) {
                logScanResults(scan, results.get());
                logger.info("Downloading Scan Report. Please wait...");
                resultsProvider.setReportFormat(reportFormat.name());
                ExecutorService executor = Executors.newSingleThreadExecutor();
                Optional<ScanResults> finalResults = results;
                Callable<String> downloadReportTask = () -> {
                    File report = getReport(resultsProvider, finalResults.get());
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
                    logger.error("Caught Exception while downloading the report : Error - "+ e.getMessage());
                } finally {
                    executor.shutdown();
                }

            } else {
                logger.error(messageBundle.getString("error.invalid.scanresult"));
            }

        } catch (Exception e) {
            logger.error(e.getMessage());
            throw e;
        }
        return results;
    }

    private IScan getScan(CloudAuthenticationHandler authHandler, IProgress progress) throws Exception {
        IScanFactory factory = new DASTScanFactory();
        DynamicAnalyzer m_scanner = getDynamicAnalyzer();
        Map<String, String> properties = getScanProperties(m_scanner, authHandler);
        return factory.create(properties, progress, authHandler);

    }
    private Map<String, String> getScanProperties(Scanner scanner, CloudAuthenticationHandler authHandler) throws Exception {

        Map<String, String> properties = scanner.getProperties();
        properties.put(CoreConstants.SCANNER_TYPE, scanner.getType());
        properties.put(CoreConstants.APP_ID, appId);
        properties.put(CoreConstants.SCAN_NAME, scanName + "_" + SystemUtil.getTimeStamp());
        properties.put(CoreConstants.EMAIL_NOTIFICATION, Boolean.toString(emailNotification));
        properties.put(FULLY_AUTOMATIC, Boolean.toString(!allowIntervention));
        properties.put(CoreConstants.SERVER_URL, authHandler.getServer());
        properties.put(CoreConstants.ACCEPT_INVALID_CERTS, Boolean.toString(authHandler.getacceptInvalidCerts()));
        if(scanFile!=null)
            properties.put(SCAN_FILE, scanFile.getAbsolutePath());
        if(presenceId!=null)
            properties.put(PRESENCE_ID, presenceId);
        if (System.getenv().containsKey("CODEBUILD_CI") && System.getenv("CODEBUILD_CI").equals("true")) {
            logger.info("Detected ClientType : AWS CodeBuild CLI");
            properties.put(CLIENT_TYPE, "AWS CodeBuild CLI");
        }

        return properties;

    }

    private DynamicAnalyzer getDynamicAnalyzer() {
        DynamicAnalyzer m_scanner = new DynamicAnalyzer(target);

         if (loginType.equals(LoginType.Automatic)) {
            m_scanner.setLoginType(ScannerConstants.AUTOMATIC);
            m_scanner.setLoginUser(loginUser);
            m_scanner.setLoginPassword(loginPassword);
        } else if(loginType.equals(LoginType.Manual)){
             m_scanner.setLoginType(RECORDED);
             m_scanner.setTrafficFile(trafficFile);
        } else{
            m_scanner.setLoginType(NONE);
        }
        m_scanner.setOptimization(optimization.name());
        m_scanner.setScanType(scanType.name());
        return m_scanner;
    }

    public File getReport(IResultsProvider provider, ScanResults results) {
        File report = new File(messageBundle.getString("report.download.location"), getReportName(provider, results));

        if (!report.isFile()) provider.getResultsFile(report, null);
        return report;
    }

    private String getReportName(IResultsProvider provider, ScanResults results) {
        String name = (provider.getType() + results.getName()).replaceAll(" ", "");
        return name + REPORT_SUFFIX + "." + provider.getResultsFormat().toLowerCase();
    }

    private Optional<ScanResults> getScanResults(IScan scan, IProgress progress, CloudAuthenticationHandler authHandler, IResultsProvider provider) throws Exception {

        String m_scanStatus = provider.getStatus();
        Optional<ScanResults> results = Optional.empty();
        int requestCounter = 0;
        logger.info(messageBundle.getString("info.wait.for.scan"));
        logger.info(messageBundle.getString("info.scan.progress"),scan.getName(),scan.getScanId());
        while (m_scanStatus != null && (m_scanStatus.equalsIgnoreCase(CoreConstants.INQUEUE) || m_scanStatus.equalsIgnoreCase(CoreConstants.RUNNING) || m_scanStatus.equalsIgnoreCase(CoreConstants.UNKNOWN)) && requestCounter < 10) {

            Thread.sleep(30000);

            if (m_scanStatus.equalsIgnoreCase(CoreConstants.UNKNOWN)) requestCounter++;
            else requestCounter = 0;

            m_scanStatus = provider.getStatus();
            if(SCAN_STATUS_READY.equalsIgnoreCase(m_scanStatus)){
                m_scanStatus=SCAN_STATUS_COMPLETED;
            }
            logger.info("Scan Status : {}" , m_scanStatus);

        }

        if (CoreConstants.FAILED.equalsIgnoreCase(m_scanStatus)) {
            String message = com.hcl.appscan.sdk.Messages.getMessage(ScanConstants.SCAN_FAILED, " Scan Name: " + scan.getName());
            if (provider.getMessage() != null && provider.getMessage().trim().length() > 0) {
                message += ", " + provider.getMessage();
            }
            logger.error(message);

        } else if (CoreConstants.UNKNOWN.equalsIgnoreCase(m_scanStatus)) {
            progress.setStatus(new Message(Message.ERROR, messageBundle.getString("error.unexpected")));
            logger.error(messageBundle.getString("error.unexpected"));

        } else {

            logger.info(messageBundle.getString("info.scan.completed"), m_scanStatus);

            String asocAppUrl = authHandler.getServer() + "main/myapps/" + appId + "/scans/" + scan.getScanId();
            ScanResults scanresults = new ScanResults(provider, scan.getName(), provider.getStatus(), provider.getFindingsCount(), provider.getCriticalCount(), provider.getHighCount(), provider.getMediumCount(), provider.getLowCount(), provider.getInfoCount(), asocAppUrl);
            results = Optional.of(scanresults);

        }

        return results;

    }

    private void logScanResults(IScan scan, ScanResults results) throws Exception {

        IScanServiceProvider scanServiceProvider = scan.getServiceProvider();
        JSONObject scanSummary = scanServiceProvider.getScanDetails(scan.getScanId());
        JSONObject createdBy = scanSummary.getJSONObject("CreatedBy");
        logger.info(messageBundle.getString("scan.summary.format"),appId,
                scanSummary.getString("AppName"),scan.getScanId(),results.getName(),
                scanSummary.getString("CreatedAt"),createdBy.getString("UserName"),
                createdBy.getString("FirstName") + " " + createdBy.getString("LastName"),
                createdBy.getString("Email"),target,scanSummary.getString("TestOptimizationLevel"),
                results.getScanServerUrl(),results.getTotalFindings(),results.getCriticalCount(),
                results.getHighCount(),results.getMediumCount(),results.getLowCount(),results.getInfoCount());
    }

}

