# Integrating Dynamic Security Scan into AWS CodeBuild and CodePipeline 🚀

✨ **Introduction** ✨

Incorporate security testing into your AWS CodeBuild and CodePipeline
workflows by leveraging the HCL AppScan Command-Line Interface (CLI)
capabilities. This tool empowers you to seamlessly conduct DAST (Dynamic
Application Security Testing) scans through HCL AppScan On Cloud. The
CLI tool also allows you to perform some additional supplementary
operations.

✨ **Prerequisites** ✨

-   You need an account at the [HCL AppScan on
    Cloud](https://cloud.appscan.com/AsoCUI/serviceui/home) service
    and an API Key and Secret for AppScan on Cloud Authentication. To
    generate an API key and secret credentials, refer to [Generating API
    Keys
    (hcltechsw.com)](https://help.hcltechsw.com/appscan/ASoC/appseccloud_generate_api_key_cm.html).

-   We recommend securely storing your API Key and Secret in an
    encrypted format using the AWS System Manager Parameter Store or the
    AWS Secrets Manager.

-   [Create an
    application](http://help.hcltechsw.com/appscan/ASoC/ent_create_application.html?query=create) on
    the service to associate with your scans.

-   You need access to an AWS account with the necessary permissions to
    configure and run AWS Code Build, Code Pipeline, or both.

-   A Target website URL to perform a dynamic scan on.

-   Access to the AppScan CLI Tool Binary hosted on Maven Central.

✨ **Integrating Dynamic Security Scan into AWS CodeBuild and
CodePipeline** ✨

This section provides instructions on configuring AWS CodeBuild for
dynamic security scans and integrating it as a stage within an AWS
CodePipeline. The AppScan CLI tool will perform the dynamic security
scan as part of the build process.

**Part 1: Configure AWS CodeBuild for Dynamic Security Scan**

**Step 1: Set Up CodeBuild Project**

1.  Open the AWS Management Console and navigate to **CodeBuild**.

2.  Click on **Create build project**.

3.  **Project configuration**:

    -   **Project name**: Enter a name for your Code Build project.

    -   **Source**: From the Source provider dropdown, choose **No
        source**.

    -   **Environment**: Choose an environment that suits your
        application (e.g., Ubuntu, Amazon Linux) and has Java 11. We
        recommend selecting Amazon Linux Coretto11 Image.\
        **Image -
        aws/codebuild/amazonlinux2-x86_64-standard:corretto11**

    -   **Buildspec**: Choose \"Use a buildspec file\" and select the
        source location of your buildspec file (usually
        **buildspec.yml**). Alternatively, you can select "Insert build
        commands" and add the build commands in the onscreen editor.

> **Example buildspec** --
~~~
version: 0.2
env:
  parameter-store:
      STAGING_ASOC_KEY: "STAGING_ASOC_KEY_ID"
      STAGING_ASOC_KEY_SECRET: "STAGING_ASOC_KEY_SECRET"
phases:
  build:
    commands:
       - wget [URL of appscan-cloud-cli jar]
       - java -jar appscan-cloud-cli-1.0.0.jar invokedynamicscan --key=$STAGING_ASOC_KEY --secret=$STAGING_ASOC_KEY_SECRET --appId=<ASoC Application ID> --scanName=<Scan Name> --target=<Target URL>
artifacts:
  files:
    - '*/AppscanReports/*'
  discard-paths: yes

~~~
In your **buildspec.yml**, add the commands to download the AppScan CLI
tool and execute the security scan. See the commands in the above
buildspec example for reference. We assume the API Key ID and Secret are
stored in the AWS System Manager Parameter Store. For more information
on Full list of CLI commands and options, refer to the [HCL Appscan Cloud CLI Readme](https://github.com/HCL-TECH-SOFTWARE/appscan-cloud-cli).

4.  **Artifacts**: Configure where the build artifacts (Scan Analysis
    Report) should be stored after the build (scan) completes. For
    Example, you can store the scan report in the Amazon S3 Bucket of
    your preference and mention the path as "AppscanReports" and the
    Namespace type as Build ID.

5.  **Logs**: Choose the desired CloudWatch settings for your build
    logs.

6.  **Service role**: If you don\'t have a service role, create a new
    one or use an existing one with the necessary permissions.

7.  **VPC**: Configure VPC settings if needed for your application.

8.  **Timeouts**: Set appropriate timeouts for your build phases.

9.  **Build badge**: Configure a build badge if desired.

10. To create the CodeBuild project, click on **Create build project**.

**Step 2: Test CodeBuild Configuration:**

1.  Trigger a build manually to ensure your build configuration is
    working as expected.

2.  Monitor the build progress in the AWS Management Console.

3.  Verify that your CLI tool successfully performs the dynamic security
    scan during the build process.

✨ **Part 2: Integrate CodeBuild into CodePipeline** ✨

**Step 1: Set Up CodePipeline:**

1.  Open the AWS Management Console and navigate to **CodePipeline**.

2.  Click on **Create pipeline**.

3.  **Pipeline settings**:

    -   **Pipeline name**: Enter a name for your pipeline.

    -   **Service role**: Choose an existing role or create a new one
        with permission to interact with CodeBuild and any necessary
        resources.

4.  **Source stage**:

    -   Choose the source provider and configure repository details.

    -   Set up the appropriate source action settings.

5.  **Build and Deployment stages**:

    -   Add and configure Build and Deploy stages to your pipeline, per
        your pipeline requirements.

6.  **Dynamic Security Analysis stage**:

    -   Click on **Add stage**.

    -   Enter a name for the stage (e.g.,
        \"**Dynamic_Security_Analysis**\").

    -   Click on **Add action group** and choose \"AWS CodeBuild\" as
        the provider.

7.  **Configure build action**:

    -   Choose the CodeBuild project you created earlier (Part 1) step.

    -   Set the appropriate action settings, including input artifacts.

8.  **Artifact stage** (Optional):

    -   Click on **Add stage**.

    -   Enter a name for the stage (e.g., \"Artifacts\").

    -   Configure actions to deploy or store your build artifacts.

9.  Click on **Next** to review your pipeline configuration.

10. Click on **Create pipeline** to create the CodePipeline.

**Step 2: Test CodePipeline Integration:**

1.  Trigger your pipeline manually or by your configured source provider
    (e.g., code commits).

2.  Monitor the pipeline execution in the AWS Management Console.

3.  Verify that the CodeBuild stage runs your CLI tool and performs the
    dynamic security scan as part of the build process.

✨ **Conclusion** ✨

You have successfully configured AWS CodeBuild to include dynamic
security scans using your published CLI tool and integrated it as a
stage within AWS CodePipeline. This integration enhances the security of
your application by automatically conducting security scans during the
CI/CD process.

Regularly monitor your pipeline\'s execution and review your CLI tool\'s
configurations to ensure your security scanning remains effective and up
to date.