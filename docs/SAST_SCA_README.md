# HCL AppScan Cloud CLI - SAST & SCA Scanning

## Overview

The HCL AppScan Cloud CLI now supports **Static Application Security Testing (SAST)** and **Software Composition Analysis (SCA)** in addition to the existing Dynamic Application Security Testing (DAST) capabilities. These features enable you to scan source code for security vulnerabilities and analyze open source dependencies for known CVEs, all from the command line.

The CLI integrates with **HCL AppScan on Cloud** and **HCL AppScan 360** and can be embedded into any CI/CD pipeline.

## Prerequisites

- Java 11 or later
- An active HCL AppScan on Cloud or AppScan 360 account
- A valid API Key and Secret with appropriate entitlements:
  - **SAST entitlement** for static analysis scans
  - **SCA entitlement** for software composition analysis scans
- An application registered in AppScan (use the `getapplications` command to retrieve application IDs)

## Available Commands

| Command | Description |
|---------|-------------|
| `invokesastscan` | Run a Static Application Security Testing (SAST) scan |
| `invokescascan` | Run a Software Composition Analysis (SCA) scan |
| `invokedynamicscan` | Run a Dynamic Application Security Testing (DAST) scan |
| `getapplications` | List application IDs from AppScan on Cloud or AppScan 360 |
| `getpresenceids` | List presence IDs from AppScan on Cloud |
| `help` | Display help information |

---

## SAST Scanning (`invokesastscan`)

The `invokesastscan` command performs static analysis on your source code to identify security vulnerabilities such as SQL injection, cross-site scripting, buffer overflows, and other code-level issues.

### Scan Methods

The SAST command supports two scan methods:

| Method | Description |
|--------|-------------|
| `createIRX` (default) | Downloads the SAClient locally, generates an IRX (Intermediate Representation eXchange) file from your source code, and uploads it to AppScan for analysis. This is the recommended method for most use cases. |
| `uploadDirect` | Uploads source files, directories, or pre-built IRX files directly to AppScan without generating an IRX locally. Useful when you already have an IRX file or want to skip the local SAClient step. |

### Options

#### Required Options

| Option | Description |
|--------|-------------|
| `--key` | AppScan on Cloud or AppScan 360 API Key |
| `--secret` | AppScan on Cloud or AppScan 360 API Secret |
| `--appId` | The application ID that this scan will be associated with |
| `--scanName` | A name to identify the scan and its results |
| `--target` | Path to the source code directory, IRX file, or zip file to scan |

#### Optional Options

| Option | Default | Description |
|--------|---------|-------------|
| `--scanMethod` | `createIRX` | Scan method: `createIRX` or `uploadDirect` |
| `--scanSpeed` | _(none)_ | Scan speed: `normal`, `fast`, `faster`, `fastest`. Faster speeds reduce scan time but may find fewer issues |
| `--openSourceOnly` | `false` | When `true`, only open source analysis (SCA) is performed |
| `--sourceCodeOnly` | `false` | When `true`, only source code is analyzed (no binary analysis). Not supported with `uploadDirect` |
| `--includeSCA` | `true` | Include Software Composition Analysis in the SAST scan for combined results |
| `--rescan` | `false` | Perform a rescan of an existing scan (requires `--scanId`) |
| `--scanId` | _(none)_ | The scan ID to rescan. Required when `--rescan=true` |
| `--reportFormat` | `html` | Report format: `html`, `pdf`, `csv`, `xml` |
| `--waitForResults` | `true` | Wait for the scan to complete before returning |
| `--failBuildNonCompliance` | `false` | Fail with exit code `12` if non-compliant issues are found |
| `--serviceUrl` | _(none)_ | Custom AppScan service URL (for AppScan 360) |
| `--acceptssl` | `false` | Accept untrusted SSL certificates (AppScan 360 only, for testing) |

#### Threshold-Based Failure (`failbuildif` subcommand)

The `failbuildif` subcommand allows you to set threshold conditions that will fail the build:

| Option | Description |
|--------|-------------|
| `--totalissuesgt` / `-ti` | Fail if total issues exceed this value |
| `--criticalissuesgt` / `-ci` | Fail if critical severity issues exceed this value |
| `--highissuesgt` / `-hi` | Fail if high severity issues exceed this value |
| `--medissuesgt` / `-mi` | Fail if medium severity issues exceed this value |
| `--lowissuesgt` / `-li` | Fail if low severity issues exceed this value |

Conditions are logically OR'd -- if any single condition is met, the build fails.

### Usage Examples

**Basic SAST scan with IRX generation:**
```bash
java -jar appscan-cloud-cli.jar invokesastscan \
  --key=<API_KEY> \
  --secret=<API_SECRET> \
  --appId=<APP_ID> \
  --scanName="MyApp-SAST-Scan" \
  --target=/path/to/source/code
```

**SAST scan with direct upload and fast scan speed:**
```bash
java -jar appscan-cloud-cli.jar invokesastscan \
  --key=<API_KEY> \
  --secret=<API_SECRET> \
  --appId=<APP_ID> \
  --scanName="MyApp-Fast-SAST" \
  --target=/path/to/source.zip \
  --scanMethod=uploadDirect \
  --scanSpeed=fast
```

**SAST scan without SCA (source code analysis only):**
```bash
java -jar appscan-cloud-cli.jar invokesastscan \
  --key=<API_KEY> \
  --secret=<API_SECRET> \
  --appId=<APP_ID> \
  --scanName="MyApp-SourceOnly" \
  --target=/path/to/source \
  --includeSCA=false \
  --sourceCodeOnly=true
```

**SAST scan with threshold-based failure:**
```bash
java -jar appscan-cloud-cli.jar invokesastscan \
  --key=<API_KEY> \
  --secret=<API_SECRET> \
  --appId=<APP_ID> \
  --scanName="MyApp-SAST-Gated" \
  --target=/path/to/source \
  failbuildif --criticalissuesgt=0 --highissuesgt=5
```

**Rescan an existing SAST scan:**
```bash
java -jar appscan-cloud-cli.jar invokesastscan \
  --key=<API_KEY> \
  --secret=<API_SECRET> \
  --appId=<APP_ID> \
  --scanName="MyApp-Rescan" \
  --target=/path/to/source \
  --rescan=true \
  --scanId=<EXISTING_SCAN_ID>
```

**Fire-and-forget (don't wait for results):**
```bash
java -jar appscan-cloud-cli.jar invokesastscan \
  --key=<API_KEY> \
  --secret=<API_SECRET> \
  --appId=<APP_ID> \
  --scanName="MyApp-Async" \
  --target=/path/to/source \
  --waitForResults=false
```

**AppScan 360 with custom service URL:**
```bash
java -jar appscan-cloud-cli.jar invokesastscan \
  --key=local_<API_KEY> \
  --secret=<API_SECRET> \
  --appId=<APP_ID> \
  --scanName="MyApp-A360-SAST" \
  --target=/path/to/source \
  --serviceUrl=https://appscan360.example.com \
  --acceptssl=true
```

---

## SCA Scanning (`invokescascan`)

The `invokescascan` command performs Software Composition Analysis to identify known vulnerabilities in open source and third-party libraries used by your application.

### Options

#### Required Options

| Option | Description |
|--------|-------------|
| `--key` | AppScan on Cloud or AppScan 360 API Key |
| `--secret` | AppScan on Cloud or AppScan 360 API Secret |
| `--appId` | The application ID that this scan will be associated with |
| `--scanName` | A name to identify the scan and its results |
| `--target` | Path to the source code directory to scan |

#### Optional Options

| Option | Default | Description |
|--------|---------|-------------|
| `--rescan` | `false` | Perform a rescan of an existing scan (requires `--scanId`) |
| `--scanId` | _(none)_ | The scan ID to rescan. Required when `--rescan=true` |
| `--reportFormat` | `html` | Report format: `html`, `pdf`, `csv`, `xml` |
| `--waitForResults` | `true` | Wait for the scan to complete before returning |
| `--failBuildNonCompliance` | `false` | Fail with exit code `12` if non-compliant issues are found |
| `--serviceUrl` | _(none)_ | Custom AppScan service URL (for AppScan 360) |
| `--acceptssl` | `false` | Accept untrusted SSL certificates (AppScan 360 only, for testing) |

#### Threshold-Based Failure (`failbuildif` subcommand)

Same as SAST -- see the `failbuildif` subcommand options above.

### Usage Examples

**Basic SCA scan:**
```bash
java -jar appscan-cloud-cli.jar invokescascan \
  --key=<API_KEY> \
  --secret=<API_SECRET> \
  --appId=<APP_ID> \
  --scanName="MyApp-SCA-Scan" \
  --target=/path/to/source/code
```

**SCA scan with PDF report:**
```bash
java -jar appscan-cloud-cli.jar invokescascan \
  --key=<API_KEY> \
  --secret=<API_SECRET> \
  --appId=<APP_ID> \
  --scanName="MyApp-SCA-Report" \
  --target=/path/to/source \
  --reportFormat=pdf
```

**SCA scan with threshold-based failure:**
```bash
java -jar appscan-cloud-cli.jar invokescascan \
  --key=<API_KEY> \
  --secret=<API_SECRET> \
  --appId=<APP_ID> \
  --scanName="MyApp-SCA-Gated" \
  --target=/path/to/source \
  failbuildif --criticalissuesgt=0 --highissuesgt=0
```

---

## SAST vs SCA: When to Use What

| Aspect | SAST (`invokesastscan`) | SCA (`invokescascan`) |
|--------|------------------------|----------------------|
| **What it scans** | Your application's source code | Open source / third-party dependencies |
| **What it finds** | Code-level vulnerabilities (SQLi, XSS, etc.) | Known CVEs in libraries |
| **Scan target** | Source code directories, IRX files, zip archives | Source code directories |
| **Combined option** | Use `--includeSCA=true` to run both SAST + SCA together | Standalone SCA only |
| **Scan methods** | `createIRX` (local IRX generation) or `uploadDirect` | N/A (uses SCAScanFactory) |
| **Use case** | Find bugs in code you write | Find vulnerabilities in code you consume |

**Tip:** For the most comprehensive analysis, use `invokesastscan` with `--includeSCA=true` (the default). This runs both SAST and SCA in a single scan, providing a unified view of your application's security posture.

---

## Scan Workflow

Both SAST and SCA commands follow the same lifecycle:

1. **Authentication** -- Validates API Key and Secret against AppScan on Cloud or AppScan 360
2. **Entitlement Check** -- Verifies the account has the required SAST or SCA subscription
3. **Target Validation** -- Confirms the specified target path exists on the local filesystem
4. **Scan Submission** -- Creates and submits the scan via the AppScan SDK
   - For SAST with `createIRX`: Downloads SAClient, generates IRX locally, then uploads
   - For SAST with `uploadDirect`: Uploads source files directly
   - For SCA: Uploads source for dependency analysis
5. **Progress Monitoring** -- Polls scan status every 30 seconds, displaying duration and progress
6. **Results Retrieval** -- Fetches findings summary (critical, high, medium, low, info counts)
7. **Report Download** -- Downloads the scan report in the specified format to `./AppscanReports/`
8. **Scan Log Download** -- Downloads scan logs as a zip file to `./AppscanReports/`
9. **Exit Code Determination** -- Returns appropriate exit code based on results and thresholds

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully, all conditions passed |
| `2` | Invalid option combination (e.g., `--waitForResults=false` with `--failBuildNonCompliance=true`) |
| `10` | Scan failed, threshold exceeded, or unexpected error |
| `12` | Non-compliant issues found (when `--failBuildNonCompliance=true`) |

## Scan Output

When `--waitForResults=true`, the CLI outputs:

1. **Real-time scan progress** -- Status, duration, and request count updated in-place
2. **Scan summary** -- Application ID, scan ID, scan name, creation details, and target
3. **Findings summary** -- Breakdown by severity (Critical, High, Medium, Low, Info)
4. **Scan result URL** -- Direct link to view the scan in the AppScan web console
5. **Report file** -- Downloaded to `./AppscanReports/<ScanType><ScanName>_report.<format>`
6. **Scan log file** -- Downloaded to `./AppscanReports/ScanLog_<timestamp>.zip`

---

## CI/CD Integration Examples

### Jenkins Pipeline (Declarative)

```groovy
pipeline {
    agent any
    stages {
        stage('SAST Scan') {
            steps {
                sh '''
                    java -jar appscan-cloud-cli.jar invokesastscan \
                      --key=${ASOC_KEY} \
                      --secret=${ASOC_SECRET} \
                      --appId=${APP_ID} \
                      --scanName="Jenkins-SAST-${BUILD_NUMBER}" \
                      --target=${WORKSPACE} \
                      --reportFormat=html \
                      failbuildif --criticalissuesgt=0 --highissuesgt=10
                '''
            }
        }
        stage('SCA Scan') {
            steps {
                sh '''
                    java -jar appscan-cloud-cli.jar invokescascan \
                      --key=${ASOC_KEY} \
                      --secret=${ASOC_SECRET} \
                      --appId=${APP_ID} \
                      --scanName="Jenkins-SCA-${BUILD_NUMBER}" \
                      --target=${WORKSPACE} \
                      failbuildif --criticalissuesgt=0
                '''
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'AppscanReports/**', allowEmptyArchive: true
        }
    }
}
```

### GitHub Actions

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: SAST Scan
        run: |
          java -jar appscan-cloud-cli.jar invokesastscan \
            --key=${{ secrets.ASOC_KEY }} \
            --secret=${{ secrets.ASOC_SECRET }} \
            --appId=${{ vars.APP_ID }} \
            --scanName="GHA-SAST-${{ github.run_number }}" \
            --target=. \
            --reportFormat=html

      - name: Upload Reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: AppscanReports/
```

### Azure DevOps

```yaml
steps:
  - task: CmdLine@2
    displayName: 'SAST Scan'
    inputs:
      script: |
        java -jar appscan-cloud-cli.jar invokesastscan \
          --key=$(ASOC_KEY) \
          --secret=$(ASOC_SECRET) \
          --appId=$(APP_ID) \
          --scanName="AzDO-SAST-$(Build.BuildNumber)" \
          --target=$(Build.SourcesDirectory) \
          failbuildif --criticalissuesgt=0 --highissuesgt=5
```

---

## Technical Details

### SDK Version

The CLI uses **HCL AppScan SDK v1.1.12**, which provides:

- `SASTScanFactory` / `SCAScanFactory` -- Scan creation via the `IScanFactory` interface
- `SASTScan` / `SCAScan` / `SAST_SCA_Scan` -- Scan execution (IRX generation, file upload, submission)
- `ServiceUtil.hasSastEntitlement()` / `hasScaEntitlement()` -- Subscription validation
- `NonCompliantIssuesResultProvider` -- Policy compliance checking
- `CloudScanServiceProvider` -- Cloud API communication with support for `?fileType=SourceCodeArchive` for non-IRX uploads

### Architecture

```
com.hcl.appscan.cli
  +-- handlers/
  |     +-- AppscanCLIApp.java          Main CLI entry point (picocli)
  |     +-- InvokeStaticScan.java       SAST command handler
  |     +-- InvokeSCAScan.java          SCA command handler
  |     +-- InvokeDynamicScan.java      DAST command handler
  |     +-- GetApplicationIds.java      List applications
  |     +-- GetPresenceIds.java         List presences
  +-- scanners/
  |     +-- Scanner.java                Abstract base scanner
  |     +-- StaticAnalyzer.java         SAST scanner model
  |     +-- SoftwareCompositionAnalyzer.java  SCA scanner model
  |     +-- DynamicAnalyzer.java        DAST scanner model
  +-- auth/
  |     +-- CloudAuthenticationHandler.java  Authentication provider
  +-- results/
  |     +-- ScanResults.java            Scan results container
  |     +-- ScanProgress.java           Progress logger
  +-- constants/
        +-- ScannerConstants.java       Scan type and property constants
        +-- CLIConstants.java           CLI-wide constants
```

### Java Version

Requires Java 11 or later (`maven.compiler.source=11`, `maven.compiler.target=11`).

### Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| `com.hcl:appscan.sdk` | 1.1.12 | AppScan SDK for scan management |
| `info.picocli:picocli` | 4.7.5 | Command-line argument parsing |
| `ch.qos.logback:logback-classic` | 1.6.3 | Logging |
| `org.fusesource.jansi:jansi` | 2.4.0 | ANSI color output in terminal |
| `org.apache.commons:commons-compress` | 1.26.0 | Archive handling (transitive from SDK) |
| `commons-io:commons-io` | 2.17.0 | File utilities (transitive from SDK) |
