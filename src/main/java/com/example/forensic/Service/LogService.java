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
import java.time.format.DateTimeParseException;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.*;
import com.itextpdf.layout.borders.SolidBorder;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

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

    public String appendLog(MultipartFile logFile, MultipartFile hashFile) throws IOException {
        LocalDateTime serverTimestamp = LocalDateTime.now();

        String originalFilename = logFile.getOriginalFilename();
        if (originalFilename == null || !originalFilename.contains("_")) {
            throw new IllegalArgumentException("파일명이 올바르지 않습니다. 형식: deviceId_logType.txt");
        }

        String[] parts = originalFilename.split("_");
        if (parts.length < 2) {
            throw new IllegalArgumentException("파일명이 올바르지 않습니다. 형식: deviceId_logType.txt");
        }

        String deviceId = parts[0];
        String logType = parts[1].replace(".txt", "");

        // 파일 내용 읽기
        List<String> lines = new BufferedReader(new InputStreamReader(logFile.getInputStream(), StandardCharsets.UTF_8))
                .lines()
                .collect(Collectors.toList());

        // 해시 파일 처리 (해시 파일이 있을 경우)
        String hash = null;
        if (hashFile != null && !hashFile.isEmpty()) {
            // 해시 파일 읽기 및 처리 (예: 첫 번째 줄을 해시로 처리하는 방식)
            hash = new BufferedReader(new InputStreamReader(hashFile.getInputStream(), StandardCharsets.UTF_8))
                    .lines()
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("해시 파일에 내용이 없습니다."));
        }

        for (String line : lines) {
            String[] logParts = line.split(" ", 3);  // 날짜, 시간, 메시지 분리
            if (logParts.length < 3) continue;

            try {
                // 날짜와 시간을 합쳐서 파싱
                String dateTimeString = logParts[0] + " " + logParts[1];
                LocalDateTime createdAt = LocalDateTime.parse(dateTimeString, FORMATTER);
                String message = logParts[2];

                Log log = new Log(deviceId, createdAt, message, logType, hash, serverTimestamp);
                logRepository.save(log);
            } catch (DateTimeParseException e) {
                throw new IllegalArgumentException("날짜 형식이 올바르지 않습니다: " + logParts[0] + " " + logParts[1]);
            }
        }

        return serverTimestamp.format(FORMATTER);
    }




    public String analyzeLogs(String deviceId, LocalDateTime startTime, LocalDateTime endTime) throws Exception {
        List<Log> logs = logRepository.findLogsWithinDuration(deviceId, startTime, endTime);
        logs.sort(Comparator.comparing(Log::getServerTimestamp));
        return generateReport(deviceId, logs, startTime, endTime);
    }

    private void addLogTable(Document document, String title, String[][] data) {
        document.add(new Paragraph(title).setBold().setFontSize(12).setMarginTop(10));

        Table table = new Table(new float[]{3, 4, 5}); // Event Type, Details, Occurrence
        table.setWidth(100);

        table.addHeaderCell(new Cell().add(new Paragraph("Event Type").setBold()));
        table.addHeaderCell(new Cell().add(new Paragraph("Details").setBold()));
        table.addHeaderCell(new Cell().add(new Paragraph("Occurrence").setBold()));

        String currentType = "";
        for (String[] row : data) {
            if (!row[0].equals(currentType)) {
                int rowspan = (int) Stream.of(data).filter(r -> r[0].equals(row[0])).count();
                table.addCell(new Cell(rowspan, 1).add(new Paragraph(row[0])));
                currentType = row[0];
            }
            table.addCell(new Cell().add(new Paragraph(row[1])));
            table.addCell(new Cell().add(new Paragraph(row[2])));
        }

        document.add(table);
    }

    public String generateReport(String deviceId, List<Log> logs, LocalDateTime startTime, LocalDateTime endTime) throws Exception {
        String fileName = "custom_report_" + deviceId + ".pdf";
        String directoryPath = "reports";
        String filePath = directoryPath + "/" + fileName;

        Files.createDirectories(Paths.get(directoryPath));

        try (PdfWriter writer = new PdfWriter(new FileOutputStream(filePath));
             PdfDocument pdf = new PdfDocument(writer);
             Document document = new Document(pdf)) {

            // 기본 보고서 제목과 기간
            document.add(new Paragraph("📌 Device Log Report: " + deviceId)
                    .setBold().setFontSize(16)
                    .setMarginBottom(10));

            document.add(new Paragraph("⏳ 분석 기간: " + startTime.format(FORMATTER) + " ~ " + endTime.format(FORMATTER))
                    .setFontSize(12)
                    .setMarginBottom(20));

            // Anti-forensic Log
            String[][] antiForensicData = {
                    {"Timestamp manipulation", "Anti-forensic event detected:", ""},
                    {"Timestamp manipulation", "SystemClockTime: Setting time of day to sec=", ""},
                    {"Timestamp manipulation", "Auto time setting enabled: false", ""},
                    {"ADB logcat -c", "Logcat buffer cleared (logcat -c detected).", ""},
                    {"Power Off or Reboot", "Device shutdown detected", ""},
                    {"File Events", "File Name (DISPLAY_NAME)", ""},
                    {"File Events", "Relative Path", ""},
                    {"File Events", "Modified After Date", ""},
                    {"File Events", "File Created", ""},
                    {"File Events", "File Revised", ""},
                    {"File Events", "File Deleted", ""}
            };

            for (String[] row : antiForensicData) {
                boolean occurrence = logs.stream().anyMatch(log -> log.getMessage().contains(row[1]));
                row[2] = occurrence ? "O" : "X";  // Set O if the keyword is found, X if not found
            }
            addLogTable(document, "Anti-forensic Log", antiForensicData);

            // Call Log
            String[][] callLogData = {
                    {"Termination of the call", "Termination of the call", ""},
                    {"Refuse incoming calls or don't answer", "Refuse incoming calls or don't answer", ""},
                    {"start an incoming call", "start an incoming call", ""},
                    {"start an outgoing call", "start an outgoing call", ""},
                    {"Ringing an incoming call", "Ringing an incoming call", ""},
                    {"Ringing an outgoing call", "Ringing an outgoing call", ""}
            };

            for (String[] row : callLogData) {
                boolean occurrence = logs.stream().anyMatch(log -> log.getMessage().contains(row[1]));
                row[2] = occurrence ? "O" : "X";  // Set O if the keyword is found, X if not found
            }
            addLogTable(document, "Call Log", callLogData);

            // SMS Log: Check if all three keywords are present
            String[][] smsLogData = {
                    {"send/receive SMS", "SMS, to/from, Message", ""}
            };
            for (String[] row : smsLogData) {
                boolean occurrence = logs.stream().anyMatch(log -> log.getMessage().contains("SMS") &&
                        log.getMessage().contains("to/from") &&
                        log.getMessage().contains("Message"));
                row[2] = occurrence ? "O" : "X";  // Set O if all keywords are found, X if not found
            }
            addLogTable(document, "SMS Log", smsLogData);

            // Bluetooth Log
            String[][] bluetoothLogData = {
                    {"connect Bluetooth", "Bluetooth connected to:", ""},
                    {"disconnect Bluetooth", "Bluetooth disconnected to:", ""},
                    {"start streaming", "A2DP streaming started on device:", ""},
                    {"stop streaming", "A2DP streaming stopped on device:", ""}
            };

            for (String[] row : bluetoothLogData) {
                boolean occurrence = logs.stream().anyMatch(log -> log.getMessage().contains(row[1]));
                row[2] = occurrence ? "O" : "X";  // Set O if the keyword is found, X if not found
            }
            addLogTable(document, "Bluetooth Log", bluetoothLogData);

            // 타임라인 추가
            String timelineReport = generateTimelineReport(deviceId, logs);  // 타임라인 보고서 생성
            document.add(new Paragraph("📅 타임라인")
                    .setBold().setFontSize(14).setMarginTop(20));
            document.add(new Paragraph(timelineReport));

        } catch (IOException e) {
            throw new IOException("PDF 생성 중 오류 발생", e);
        }

        return "리포트가 생성되었습니다: " + filePath;
    }

    public String readLog(String deviceId, String logType) {
        List<Log> logs = logRepository.findByDeviceIdAndLogType(deviceId, logType);
        return logs.toString();
    }

    public boolean verifyLogIntegrity(String deviceId, String logType, String hash) {
        Path hashFilePath = Paths.get("log", deviceId, logType, "hash.txt");

        if (!Files.exists(hashFilePath)) {
            return false;
        }

        try (Stream<String> lines = Files.lines(hashFilePath, StandardCharsets.UTF_8)) {
            return lines.anyMatch(line -> line.contains(hash));
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    public String generateTimelineReport(String deviceId, List<Log> logs) throws Exception {
        StringBuilder report = new StringBuilder();

        // createdAt으로 정렬된 타임라인 출력
        List<Log> createdAtSortedLogs = logs.stream()
                .sorted(Comparator.comparing(Log::getCreatedAt))
                .collect(Collectors.toList());

        report.append("⏳ createdAt 기준 타임라인:\n");
        for (Log log : createdAtSortedLogs) {
            report.append(String.format("%s %s\n", log.getCreatedAt().format(FORMATTER), log.getMessage()));

            // 해시 값 검증
            boolean isValid = verifyLogHash(log);
            String validStatus = isValid ? "valid" : "invalid";
            String hashMessage = String.format("Hash: %s, Hash validation result: %s\n", log.getHash(), validStatus);

            report.append(hashMessage);
        }

        report.append("\n");

        // serverTimestamp로 정렬된 타임라인 출력
        List<Log> serverTimestampSortedLogs = logs.stream()
                .sorted(Comparator.comparing(Log::getServerTimestamp))
                .collect(Collectors.toList());

        report.append("⏳ serverTimestamp 기준 타임라인:\n");
        for (Log log : serverTimestampSortedLogs) {
            report.append(String.format("%s %s\n", log.getServerTimestamp().format(FORMATTER), log.getMessage()));

            // 해시 값 검증
            boolean isValid = verifyLogHash(log);
            String validStatus = isValid ? "valid" : "invalid";
            String hashMessage = String.format("Hash: %s, Hash 검증 결과: %s\n", log.getHash(), validStatus);

            report.append(hashMessage);
        }

        return report.toString();
    }

    private boolean verifyLogHash(Log log) {
        try {
            // createdAt과 message를 결합하여 해시 값 계산
            String messageToHash = log.getCreatedAt().format(FORMATTER) + log.getMessage();
            String calculatedHash = calculateMessageHash(messageToHash);

            // DB에 저장된 해시 값과 비교
            return log.getHash().equals(calculatedHash);
        } catch (Exception e) {
            return false;
        }
    }


    private String calculateMessageHash(String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(message.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hashBytes);
    }
}
