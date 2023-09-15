 # HCL Appscan Cloud CLI 📝  
  The HCL Appscan command-line utility (CLI) is designed to streamline Dynamic Application Security Testing within a Continuous Integration and Continuous Deployment (CICD) environment. This tool can be seamlessly integrated into any CICD platform or used independently.  
  
## Get Started 🚀  

- You need an account at the HCL AppScan on Cloud service and an API Key and Secret for AppScan on Cloud Authentication. To generate an API key and secret credentials, refer to Generating API Keys (hcltechsw.com).
- Create an application on the service to associate with your scans.
- A Target website URL to perform a dynamic scan on.
- Access to the AppScan CLI Tool Binary hosted on Maven Central.

## CLI Tool Usage Manual  ✨

## Commands

### getapplications

Gets list of application id's from Appscan on Cloud

~~~bash  
Usage: appscan getapplications [-hV] --key=<key> --secret=<secret> [COMMAND]

  -h, --help              Show this help message and exit.
  -V, --version           Print version information and exit.
      --key=<key>         [Required] ASoC API Key
      --secret=<secret>   [Required] ASoC API Secret
Commands:
  help : Display help information about the specified command
~~~

### invokedynamicscan

This command serves the purpose of configuring and triggering the initiation of a Dynamic Security Analysis Scan on AppScan on Cloud. This operation is designed to seamlessly retrieve the outcomes of the scan once it has concluded. The yielded results encompass a list of pinpointed vulnerabilities, comprehensive analytical documents, and associated URLs for these reports. Moreover, the Command Line Interface (CLI) can be customized by employing specific command line options to establish criteria for failure instances. Consequently, this enables the CLI to transmit a signal indicating success or failure to the designated pipeline in a well-defined manner.

~~~bash  
Usage: appscan invokedynamicscan [-hV] [--allowIntervention]
                                 [--emailNotification]
                                 [--failBuildNonCompliance] [--waitForResults]
                                 --appId=<appId> --key=<key>
                                 [--loginPassword=<loginPassword>]
                                 [--loginType=<loginType>]
                                 [--loginUser=<loginUser>]
                                 [--optimization=<optimization>]
                                 [--presenceId=<presenceId>]
                                 [--reportFormat=<reportFormat>]
                                 [--scanFile=<scanFile>] --scanName=<scanName>
                                 [--scanType=<scanType>] --secret=<secret>
                                 --target=<target>
                                 [--trafficFile=<trafficFile>] [COMMAND]

Options:
  -h, --help                Show this help message and exit.
  -V, --version             Print version information and exit.
      --key=<key>           [Required] Appscan on Cloud API Key
      --secret=<secret>     [Required] Appscan on Cloud API Secret
      --appId=<appId>       [Required] The HCL AppScan on Cloud application
                              that this scan will be associated with
      --scanName=<scanName> [Required] Specify a name to use for the scan. This
                              value is used to distinguish this scan and its
                              results from others.
      --target=<target>     [Required] Enter the URL from where you want the
                              scan to start exploring the site.
      --scanType=<scanType> [Optional] Mention whether your site is a Staging
                              site (under development) or a Production site
                              (live and in use). Valid values : Production,
                              Staging
                              Default: Production
      --optimization=<optimization>
                            [Optional] You can reduce scan time by choosing a
                              balance between speed and issue coverage. Valid
                              values : Fast, Faster, Fastest, NoOptimization
                              Default: fast
      --emailNotification   [Optional] Send the user an email when analysis is
                              complete. Valid values : true , false
                              Default: false
      --reportFormat=<reportFormat>
                            [Optional] Specify format for the scan result
                              report. Valid values : html, pdf, csv, xml.
                              Default: html
      --allowIntervention   [Optional] When set to true, our scan enablement
                              team will step in if the scan fails, or if no
                              issues are found, and try to fix the
                              configuration. This may delay the scan result.
                              Default: false
      --presenceId=<presenceId>
                            [Optional] For sites not available on the internet,
                              provide the ID of the AppScan Presence that can
                              be used for the scan.
      --waitForResults      [Optional] Suspend the job until the security
                              analysis results are available.
                              Default: true
      --failBuildNonCompliance
                            [Optional] Fail the job if one or more issues are
                              found which are non compliant with respect to the
                              selected application's policies.
                              Default: false
      --scanFile=<scanFile> [Optional] The path to a scan template file (.scan
                              or .scant).
                              Default: null
      --loginType=<loginType>
                            [Optional] Which Login method do you want to use?
                              Type None if login not required. Type Automatic
                              if you want to provide loginUser and password.
                              Type Manual if you want to specify Login Sequence
                              File. Valid values : None, Automatic, Manual
                              Default: None
      --loginUser=<loginUser>
                            [Optional] If your app requires login, enter valid
                              user credentials so that Application Security on
                              Cloud can log in to the site.
      --loginPassword=<loginPassword>
                            [Optional] If your app requires login, enter valid
                              user credentials so that Application Security on
                              Cloud can log in to the site.
      --trafficFile=<trafficFile>
                            [Optional] Provide a path to the login sequence
                              file data. Supported file type: CONFIG: AppScan
                              Activity Recorder file.
                              Default: null
Commands:
  help         Display help information about the specified command.
  failbuildif  [Optional] A list of conditions that will fail the build. These
                 conditions are logically "OR"'d together, so if one of the
                 conditions is met, the build will fail.

 Usage: appscan invokedynamicscan failbuildif [-ci=<arg4>] [-hi=<arg1>] [-li=<arg3>] [-mi=<arg2>] [-ti=<arg0>] 

 Options 

        -ci, --criticalissuesgt=<arg4> 
            Fail build if critical sev issues greater than 

        -hi, --highissuesgt=<arg1> 

          Fail build if high sev issues greater than 

        -li, --lowissuesgt=<arg3> 

          Fail build if low sev issues greater than 

        -mi, --medissuesgt=<arg2> 

          Fail build if medium sev issues greater than 

        -ti, --totalissuesgt=<arg0> 

          Fail build if total issues are greater than 
~~~

### getpresenceids

Gets list of presence id’s from Appscan on Cloud

~~~bash
Usage: appscan getpresenceids [-hV] --key=<key> --secret=<secret> [COMMAND]
Get list of presence id's from Appscan on Cloud
  -h, --help              Show this help message and exit.
  -V, --version           Print version information and exit.
      --key=<key>         [Required] ASoC API Key
      --secret=<secret>   [Required] ASoC API Secret
~~~

### help

Display help information about the specified command.
  
