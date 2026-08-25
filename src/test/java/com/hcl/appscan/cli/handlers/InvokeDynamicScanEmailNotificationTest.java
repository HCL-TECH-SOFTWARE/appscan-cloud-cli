package com.hcl.appscan.cli.handlers;

import com.hcl.appscan.cli.auth.CloudAuthenticationHandler;
import com.hcl.appscan.cli.scanners.DynamicAnalyzer;
import com.hcl.appscan.cli.scanners.Scanner;
import com.hcl.appscan.sdk.CoreConstants;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InvokeDynamicScanEmailNotificationTest {

    @ParameterizedTest
    @ValueSource(strings = {"true", "false"})
    void acceptsLegacyEmailNotificationValuesWithoutAddingThemToScanProperties(String value) throws Exception {
        InvokeDynamicScan command = parseCommand(value);

        String output = captureWarningOutput(command);
        Map<String, String> properties = getScanProperties(command);
        assertFalse(properties.containsKey(CoreConstants.EMAIL_NOTIFICATION));
        String normalizedOutput = normalizeLineEndings(output).trim();
        assertTrue(normalizedOutput.contains("Warning: Email Notification setting is obsolete"));
        assertTrue(normalizedOutput.contains("Warning: Email Notification setting is obsolete\nThe email notification setting for scans is obsolete, but the scan continues normally. Manage email notifications in your AppScan on Cloud notification settings.\nTo learn more, see Email notifications: https://help.hcl-software.com/appscan/ASoC/r_email_notifications.html"));
        assertFalse(normalizedOutput.contains("\n\n"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "enabled", "1"})
    void rejectsInvalidLegacyEmailNotificationValues(String value) {
        assertThrows(CommandLine.ParameterException.class, () -> parseCommand(value));
    }

    @Test
    void hidesEmailNotificationFromGeneratedHelp() {
        CommandLine commandLine = new CommandLine(new InvokeDynamicScan());
        String usage = commandLine.getUsageMessage();

        assertFalse(usage.contains("--emailNotification"));
    }

    @Test
    void doesNotWarnWhenLegacyEmailNotificationOptionIsOmitted() throws Exception {
        InvokeDynamicScan command = parseCommand(null);
        String output = captureWarningOutput(command);
        assertTrue(output.isBlank());
    }

    private InvokeDynamicScan parseCommand(String emailNotification) {
        InvokeDynamicScan command = new InvokeDynamicScan();
        CommandLine commandLine = new CommandLine(command);
        commandLine.setCaseInsensitiveEnumValuesAllowed(true);
        String[] requiredOptions = {
                "--key", "key",
                "--secret", "secret",
                "--appId", "app-id",
                "--scanName", "scan-name",
                "--target", "https://example.com"
        };

        if (emailNotification == null) {
            commandLine.parseArgs(requiredOptions);
        } else {
            String[] options = new String[requiredOptions.length + 2];
            System.arraycopy(requiredOptions, 0, options, 0, requiredOptions.length);
            options[requiredOptions.length] = "--emailNotification";
            options[requiredOptions.length + 1] = emailNotification;
            commandLine.parseArgs(options);
        }
        return command;
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> getScanProperties(InvokeDynamicScan command) throws Exception {
        Method method = InvokeDynamicScan.class.getDeclaredMethod(
                "getScanProperties", Scanner.class, CloudAuthenticationHandler.class);
        method.setAccessible(true);
        return (Map<String, String>) method.invoke(
                command, new DynamicAnalyzer("https://example.com"), new TestAuthenticationHandler());
    }

    private void invokeEmailNotificationWarning(InvokeDynamicScan command) throws Exception {
        Method method = InvokeDynamicScan.class.getDeclaredMethod("warnIfEmailNotificationProvided");
        method.setAccessible(true);
        method.invoke(command);
    }

    private String captureWarningOutput(InvokeDynamicScan command) throws Exception {
        PrintStream originalOut = System.out;
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (PrintStream captureStream = new PrintStream(outputStream, true, StandardCharsets.UTF_8)) {
            System.setOut(captureStream);
            invokeEmailNotificationWarning(command);
        } finally {
            System.setOut(originalOut);
        }
        return outputStream.toString(StandardCharsets.UTF_8);
    }

    private String normalizeLineEndings(String value) {
        return value.replace("\r\n", "\n").replace("\r", "\n");
    }

    private static class TestAuthenticationHandler extends CloudAuthenticationHandler {
        @Override
        public String getServer() {
            return "https://example.com";
        }

        @Override
        public boolean getacceptInvalidCerts() {
            return false;
        }
    }
}
