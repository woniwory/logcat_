package com.example.forensic.Service;

import com.example.forensic.dto.LogRequest;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

@Service
public class LogService {

    private static final String LOG_DIRECTORY = "logs/";

    public String appendLog(LogRequest logRequest) {
        try {
            // Ensure the log directory exists
            Files.createDirectories(Paths.get(LOG_DIRECTORY));

            // Get the log file name
            String logFileName = LOG_DIRECTORY + logRequest.getLogType() + ".txt";

            // Format the log entry
            String logEntry = logRequest.getTimestamp() + " - " + logRequest.getMessage() + System.lineSeparator();

            // Write to the log file
            Files.write(Paths.get(logFileName), logEntry.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);

            // Return the written content
            return logEntry;

        } catch (IOException e) {
            throw new RuntimeException("Failed to write log file", e);
        }
    }

    public String readLog(String logType) {
        try {
            String logFileName = LOG_DIRECTORY + logType + ".txt";
            Path logFilePath = Paths.get(logFileName);

            if (!Files.exists(logFilePath)) {
                throw new RuntimeException("Log file not found: " + logFileName);
            }

            // Read the entire file content
            return Files.readString(logFilePath);

        } catch (IOException e) {
            throw new RuntimeException("Failed to read log file", e);
        }
    }


}
