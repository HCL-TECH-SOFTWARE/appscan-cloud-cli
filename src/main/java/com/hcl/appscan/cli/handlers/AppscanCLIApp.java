/*
 *
 * Copyright 2023,2024 HCL America, Inc.
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


import com.hcl.appscan.cli.exception.ShortErrorMessageHandler;
import org.fusesource.jansi.AnsiConsole;
import picocli.CommandLine;

import static picocli.CommandLine.*;
import static picocli.CommandLine.Command;
import static picocli.CommandLine.Help.Ansi.Style.*;
import static picocli.CommandLine.Help.Ansi.Style.italic;

@Command(
        name = "-",
        subcommands = {
                GetApplicationIds.class,
                InvokeDynamicScan.class,
                GetPresenceIds.class,
                HelpCommand.class
        },
        mixinStandardHelpOptions = true, version = "AppScan CLI v1.0",headerHeading = "@|bold,underline Usage|@:%n%n",
        synopsisHeading = "%n",
        header = "HCL AppScan CLI Utility to streamline Dynamic Application Security Testing.",
        description = "The HCL AppScan command-line utility (CLI) is designed to streamline Dynamic Application Security Testing within a Continuous Integration and Continuous Deployment (CICD) environment. This tool can be seamlessly integrated into any CICD platform or used independently." ,
        optionListHeading = "%n@|bold,underline Options|@:%n" ,
        descriptionHeading = "%n@|bold,underline Description|@:%n%n"
)
public class AppscanCLIApp implements Runnable {
    public static void main(String[] args) {
        CommandLine commandLine = new CommandLine(new AppscanCLIApp());
        commandLine.setCaseInsensitiveEnumValuesAllowed(true);
        commandLine.setParameterExceptionHandler(new ShortErrorMessageHandler());
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
        System.out.println("HCL AppScan CLI");
    }
}