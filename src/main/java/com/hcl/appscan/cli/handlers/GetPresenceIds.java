/*
 * *
 *  * @ Copyright HCL Technologies Ltd. 2023.
 *  * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 *
 */

package com.hcl.appscan.cli.handlers;

import com.hcl.appscan.cli.auth.CloudAuthenticationHandler;
import com.hcl.appscan.sdk.presence.CloudPresenceProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.Callable;

import static picocli.CommandLine.*;

@Command(name = "getpresenceids" , sortOptions = false, mixinStandardHelpOptions = true , subcommands = {HelpCommand.class} ,
        description ="Get list of presence id's from Appscan on Cloud"
)
public class GetPresenceIds implements Callable<Integer> {

    private static final Logger logger = LoggerFactory.getLogger(GetPresenceIds.class);

    @Option(names = {"--key"}, description = "[Required] ASoC API Key", required = true , order = 1)
    private String key;
    @Option(names = {"--secret"}, description = "[Required] ASoC API Secret", required = true , order = 2)
    private String secret;


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
        try {
            authHandler.updateCredentials(key, secret);
        } catch (Exception e) {
            logger.error("Error in Auth-handler" + e);
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