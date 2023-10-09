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
import com.hcl.appscan.sdk.app.CloudApplicationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.Callable;

import static picocli.CommandLine.*;

@Command(name = "getapplications" , sortOptions = false, mixinStandardHelpOptions = true , subcommands = {HelpCommand.class} ,
        description ="Get list of application id's from AppScan on Cloud" , footer = "Copyright 2023 HCL America, Inc."
)
public class GetApplicationIds implements Callable<Integer> {

    private static final Logger logger = LoggerFactory.getLogger(GetApplicationIds.class);

    @Option(names = {"--key"}, description = "[Required] AppScan on Cloud API Key", required = true , order = 1)
    private String key;
    @Option(names = {"--secret"}, description = "[Required] AppScan on Cloud API Secret", required = true , order = 2)
    private String secret;


    @Override
    public Integer call() {
        try{
            printApplicationsList();
            return 0;
        }catch (Exception e){
            return 2;
        }
    }

    private void printApplicationsList() throws Exception {
        CloudAuthenticationHandler authHandler = new CloudAuthenticationHandler();
        try {
            authHandler.updateCredentials(key, secret);
        } catch (Exception e) {
            logger.error("Error in authenticating the request. Please check the credentials!");
            throw e;
        }
        try {
            Map<String, String> applications = getApplications(authHandler);
            System.out.println("Application ID \t\t\t\t\t\t\tApplication Name");
            System.out.println("---------------------------------------------------------------------------------");
            for (Map.Entry<?, ?> entry : applications.entrySet()) {
                System.out.printf("%-15s\t-\t%s%n", entry.getKey(), entry.getValue());
            }

        } catch (Exception e) {
            logger.error(e.getMessage());
            throw e;
        }
    }

    private static Map<String, String> getApplications(CloudAuthenticationHandler authHandler) throws Exception {
        CloudApplicationProvider applicationProvider = new CloudApplicationProvider(authHandler);
        return applicationProvider.getApplications();
    }

}