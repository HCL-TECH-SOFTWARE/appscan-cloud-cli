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
import com.hcl.appscan.sdk.presence.CloudPresenceProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.ResourceBundle;
import java.util.concurrent.Callable;

import static picocli.CommandLine.*;

@Command(name = "getpresenceids" , sortOptions = false, mixinStandardHelpOptions = true , subcommands = {HelpCommand.class} ,
        description ="Get list of presence id's from AppScan on Cloud"
)
public class GetPresenceIds implements Callable<Integer> {

    private static final Logger logger = LoggerFactory.getLogger(GetPresenceIds.class);
    @Spec
    Model.CommandSpec spec;

    ResourceBundle messageBundle = ResourceBundle.getBundle("messages");
    @Option(names = {"--key"}, description = "[Required] AppScan on Cloud API Key", required = true , order = 1)
    private String key;
    @Option(names = {"--secret"}, description = "[Required] AppScan on Cloud API Secret", required = true , order = 2)
    private String secret;

    @Option(names = {"--serviceUrl"}, description = "[Required] AppScan Service URL", required = false , order = 3)
    private String serviceUrl;

    private Boolean allowUntrusted;

    @Option(names = {"--allowUntrusted"},defaultValue = "false",  paramLabel = "BOOLEAN" , description = "[Optional] Set to true to enable untrusted connection to AppScan 360° service", required = false ,showDefaultValue = Help.Visibility.ALWAYS , order = 4)
    public void setAllowUntrusted(String value) {
        boolean invalid = !"true".equalsIgnoreCase(value) && !"false".equalsIgnoreCase(value);

        if (invalid) {
            throw new ParameterException(spec.commandLine(),
                    String.format(messageBundle.getString("error.invalid.allowUntrusted"), value));
        }
        allowUntrusted = Boolean.parseBoolean(value);
    }
    @Override
    public Integer call() {
        try{
            printPresenceIdList();
            return 0;
        }catch (Exception e){
            return 2;
        }
    }

    private void printPresenceIdList() throws Exception {
        CloudAuthenticationHandler authHandler = new CloudAuthenticationHandler();
        if(null!=serviceUrl){
            authHandler = new CloudAuthenticationHandler(serviceUrl , allowUntrusted);
        }else{
            authHandler = new CloudAuthenticationHandler();
        }
        try {
            authHandler.updateCredentials(key, secret);
        } catch (Exception e) {
            logger.error("Error in authenticating the request. Please check the credentials!");
            throw e;
        }
        try {
            Map<String, String> presenceMap = getPresenceMap(authHandler);
            System.out.println("Presence ID \t\t\t\t\t\t\tPresence Name");
            System.out.println("---------------------------------------------------------------------------------");
            for (Map.Entry<?, ?> entry : presenceMap.entrySet()) {
                System.out.printf("%-15s\t-\t%s%n", entry.getKey(), entry.getValue());
            }

        } catch (Exception e) {
            logger.error(e.getMessage());
            throw e;
        }
    }

    private static Map<String, String> getPresenceMap(CloudAuthenticationHandler authHandler) throws Exception {
        return new CloudPresenceProvider(authHandler).getPresences();
    }

}