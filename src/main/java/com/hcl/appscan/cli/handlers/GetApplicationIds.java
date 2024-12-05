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

import com.hcl.appscan.cli.auth.CloudAuthenticationHandler;
import com.hcl.appscan.cli.scanners.ValidationUtil;
import com.hcl.appscan.sdk.app.CloudApplicationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.ResourceBundle;
import java.util.concurrent.Callable;

import static picocli.CommandLine.*;

@Command(name = "getapplications" , sortOptions = false, mixinStandardHelpOptions = true , subcommands = {HelpCommand.class} ,
        description ="Get list of application id's from AppScan on Cloud or AppScan 360"
)
public class GetApplicationIds implements Callable<Integer> {

    private static final Logger logger = LoggerFactory.getLogger(GetApplicationIds.class);

    @Spec
    Model.CommandSpec spec;

    ResourceBundle messageBundle = ResourceBundle.getBundle("messages");
    @Option(names = {"--key"}, description = "[Required] AppScan on Cloud or AppScan 360 API Key", required = true , order = 2)
    private String key;
    @Option(names = {"--secret"}, description = "[Required] AppScan on Cloud or AppScan 360 API Secret", required = true , order = 3)
    private String secret;

    @Option(names = {"--serviceUrl"}, description = "[Required] AppScan Service URL", required = false , order = 1)
    private String serviceUrl;

    private Boolean acceptssl;

    @Option(names = {"--acceptssl"},defaultValue = "false",  paramLabel = "BOOLEAN" , description = "[Optional] Ignore untrusted certificates when connecting to AppScan 360. Only intended for testing purposes. Not applicable to AppScan on Cloud.", required = false ,showDefaultValue = Help.Visibility.ALWAYS , order = 4)
    public void setAcceptssl(String value) {

        if(null!=key && !key.startsWith("local_") && (!value.isBlank()&&!"false".equalsIgnoreCase(value))){
            logger.warn(messageBundle.getString("error.acceptssl.without.a360"));
        }

        if(null!=key && key.startsWith("local_")){
            boolean invalid = !"true".equalsIgnoreCase(value) && !"false".equalsIgnoreCase(value);

            if (invalid) {
                throw new ParameterException(spec.commandLine(),
                        String.format(messageBundle.getString("error.invalid.acceptssl"), value));
            }else if ("true".equalsIgnoreCase(value) && serviceUrl==null){
                throw new ParameterException(spec.commandLine(),
                        String.format(messageBundle.getString("error.acceptssl.without.serviceurl")));
            }
            acceptssl = Boolean.parseBoolean(value);
        }

    }

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
        CloudAuthenticationHandler authHandler;
        if(null!=serviceUrl && key.startsWith("local_")){
            if(serviceUrl.endsWith("/")){
                serviceUrl = serviceUrl.substring(0, serviceUrl.length()-1);
            }
            boolean isValidURL = ValidationUtil.checkASoCConnectivity(serviceUrl,acceptssl);
            if(!isValidURL){
                throw new ParameterException(spec.commandLine(),
                        String.format(messageBundle.getString("error.unreachable.serviceurl")));
            }
             authHandler = new CloudAuthenticationHandler(serviceUrl , acceptssl);
        }else{
             authHandler = new CloudAuthenticationHandler();
        }


        try {
            authHandler.updateCredentials( key, secret );
        } catch (Exception e) {
            //logger.error("Error in authenticating the request. Please check the credentials!");
            logger.error(e.getMessage());
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