package com.example.forensic.Service;

import com.example.forensic.dto.LogRequest;
import com.example.forensic.Entity.Log;
import com.example.forensic.Repository.LogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Service
public class LogService {

    @Autowired
    private LogRepository logRepository;

    private static final ZoneId KST_ZONE = ZoneId.of("Asia/Seoul");
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private String calculateFileHash(Path filePath) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        try (BufferedReader reader = Files.newBufferedReader(filePath)) {
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            byte[] textBytes = content.toString().getBytes(StandardCharsets.UTF_8);
            digest.update(textBytes);
        }

        byte[] hashBytes = digest.digest();
        return bytesToHex(hashBytes);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public String appendLogAndSaveHash(LogRequest logRequest) throws IOException, NoSuchAlgorithmException {
        LocalDateTime serverTimestamp = LocalDateTime.parse("2025-02-17T15:08:19");

        Log log = new Log(
                logRequest.getDeviceId(),
                logRequest.getCreatedAt(),
                logRequest.getMessage(),
                logRequest.getLogType(),
                logRequest.getFileHash(),
                serverTimestamp
        );

        try {
            logRepository.save(log);
        } catch (Exception e) {
            throw new IOException("DB connection failed, cannot write to log file.", e);
        }

        Path logTypePath = Paths.get("log", logRequest.getDeviceId(), logRequest.getLogType());
        Files.createDirectories(logTypePath);

        Path logFile = logTypePath.resolve(logRequest.getLogType() + ".txt");

        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(logFile,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND))) {
            writer.printf("%s %s\n",
                    logRequest.getCreatedAt().format(FORMATTER),
                    logRequest.getMessage());
            writer.printf(" - [INFO] %s serverTimestamp : %s\n",
                    logRequest.getCreatedAt().format(FORMATTER),
                    serverTimestamp.format(FORMATTER));
        }

        String hash = calculateFileHash(logFile);
        Path hashFile = logTypePath.resolve("hash.txt");

        String formattedHash = String.format(
                "[%s] %s's SHA-256 Hash:%s\n",
                logRequest.getCreatedAt().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
                logRequest.getLogType() + ".txt",
                hash
        );

        Files.writeString(hashFile, formattedHash, StandardOpenOption.CREATE, StandardOpenOption.APPEND);

        log.setFileHash(hash);
        logRepository.save(log);

        return serverTimestamp.format(FORMATTER);
    }

    public String readLog(String deviceId, String logType) {
        List<Log> logs = logRepository.findByDeviceIdAndLogType(deviceId, logType);
        return logs.toString();
    }
}
