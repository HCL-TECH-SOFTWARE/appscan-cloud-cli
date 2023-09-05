/*
 * *
 *  * @ Copyright HCL Technologies Ltd. 2023.
 *  * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 *
 */

package com.hcl.appscan.cli.handlers;


import org.fusesource.jansi.AnsiConsole;
import picocli.CommandLine;

import static picocli.CommandLine.*;
import static picocli.CommandLine.Command;
import static picocli.CommandLine.Help.Ansi.Style.*;
import static picocli.CommandLine.Help.Ansi.Style.italic;

@Command(
        name = "appscan",
        subcommands = {
                GetApplicationIds.class,
                InvokeDynamicScan.class,
                GetPresenceIds.class,
                HelpCommand.class
        },
        mixinStandardHelpOptions = true, version = "Appscan CLI v1.0",headerHeading = "@|bold,underline Usage|@:%n%n",
        synopsisHeading = "%n",
        header = "HCL AppScan CLI Utility to streamline Dynamic Application Security Testing.",
        description = "The HCL Appscan command-line utility (CLI) is designed to streamline Dynamic Application Security Testing within a Continuous Integration and Continuous Deployment (CICD) environment. This versatile tool can be seamlessly integrated into any CICD platform or used independently." ,
        optionListHeading = "%n@|bold,underline Options|@:%n" ,
        descriptionHeading = "%n@|bold,underline Description|@:%n%n"
)
public class AppscanCLIApp implements Runnable {
    public static void main(String[] args) {
        CommandLine commandLine = new CommandLine(new AppscanCLIApp());
        commandLine.setCaseInsensitiveEnumValuesAllowed(true);
        Help.ColorScheme colorScheme = createColorScheme();
        AnsiConsole.systemInstall();
        int exitCode = commandLine.setColorScheme(colorScheme).execute(args);
        AnsiConsole.systemUninstall();
        System.out.println("Process finished with exit code : "+exitCode);
        System.exit(exitCode);

    }
    private static Help.ColorScheme createColorScheme() {

        return new Help.ColorScheme.Builder()
                .commands    (bold, underline)    // combine multiple styles
                .options     (fg_yellow)                // yellow foreground color
                .parameters  (fg_yellow)
                .optionParams(italic)
                .errors      (fg_red, bold)
                .stackTraces (italic)
                .applySystemProperties() // optional: allow end users to customize
                .build();
    }
    @Override
    public void run() {
        System.out.println("HCL Appscan CLI");
    }
}