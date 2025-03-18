package com.example.forensic.Service;


import com.example.forensic.dto.LogRequest;
import com.example.forensic.Entity.Log;
import com.example.forensic.Repository.LogRepository;
import com.itextpdf.kernel.colors.DeviceGray;
import com.itextpdf.kernel.colors.Color;  // Color 클래스 import
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.layout.borders.Border;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
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
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
    private static final Pattern TIMESTAMP_PATTERN = Pattern.compile("^(.*?)(?:;\\s*serverTimestamp:\\s*(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}))?$");


    private String calculateFileHash(Path filePath) throws IOException, NoSuchAlgorithmException {

        try (InputStream inputStream = Files.newInputStream(filePath)) {
            String content = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))
                    .lines()
                    .collect(Collectors.joining("\n"));

            return calculateMessageHash(content);
        }
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

    private String calculateFileHash(MultipartFile file) throws IOException, NoSuchAlgorithmException {
        // 파일 내용을 문자열로 읽기
        InputStream inputStream = file.getInputStream();
        String content = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))
                .lines()
                .collect(Collectors.joining("\n"));

        // 메시지 해시 계산
        return calculateMessageHash(content);
    }


    public String appendLog(MultipartFile logFile, MultipartFile hashFile) throws IOException, NoSuchAlgorithmException {

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

        // 해시 파일 처리
        String expectedHash = null;
        if (hashFile != null && !hashFile.isEmpty()) {
            expectedHash = new BufferedReader(new InputStreamReader(hashFile.getInputStream(), StandardCharsets.UTF_8))
                    .lines()
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("해시 파일에 내용이 없습니다."));
        }

        // 로그 파일 전체에 대해 해시 계산
        String logFileHash = calculateFileHash(logFile);

        // 해시 값이 다르면 로그를 저장하지 않음
        if (expectedHash != null && !logFileHash.equals(expectedHash)) {
            System.out.println("계산된 해시값(logfile): " + logFileHash);
            System.out.println("hash.txt 해시값: " + expectedHash);
            throw new IllegalArgumentException("로그 파일의 해시값이 hash.txt의 해시값과 일치하지 않습니다. \n로그 파일 해시: " + logFileHash + "\nExpected 해시: " + expectedHash);
        }

        // 로그 파일 내용 읽기
        List<String> lines = new BufferedReader(new InputStreamReader(logFile.getInputStream(), StandardCharsets.UTF_8))
                .lines()
                .collect(Collectors.toList());

        if (lines.isEmpty()) {
            throw new IllegalArgumentException("로그 파일이 비어 있습니다.");
        }

        // 전체 로그에 대해 동일한 해시값을 설정하여 저장
        for (String line : lines) {
            String[] logParts = line.split(" ", 3);  // 날짜, 시간, 메시지 분리
            if (logParts.length < 3) continue;

            try {
                // 날짜와 시간을 합쳐서 파싱
                String dateTimeString = logParts[0] + " " + logParts[1];
                LocalDateTime createdAt = LocalDateTime.parse(dateTimeString, FORMATTER);
                String message = logParts[2];

                LocalDateTime serverTimestamp = null;

                // 서버 타임스탬프 추출을 위한 정규식 패턴 (예: "; serverTimestamp: 2025-02-18 14:08:06")
                Pattern timestampPattern = Pattern.compile(";\\s*serverTimestamp:\\s*(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})");
                Matcher matcher = timestampPattern.matcher(message);
                if (matcher.find()) {
                    String extractedTimestamp = matcher.group(1);  // "2025-02-18 14:08:06"

                    // 타임스탬프를 추출한 후, 메시지에서 제거
                    message = message.replace(matcher.group(0), "").trim();  // ; serverTimestamp 부분 제거

                    try {
                        serverTimestamp = LocalDateTime.parse(extractedTimestamp, DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
                    } catch (DateTimeParseException e) {
                        throw new IllegalArgumentException("serverTimestamp 날짜 형식이 올바르지 않습니다: " + extractedTimestamp);
                    }
                } else {
                    // 서버 타임스탬프를 찾을 수 없으면 예외 발생
                    throw new IllegalArgumentException("serverTimestamp를 로그 메시지에서 찾을 수 없습니다.");
                }

                // 로그 객체 저장 (모든 로그 항목에 동일한 해시값을 적용)
                Log log = new Log(deviceId, createdAt, message, logType, logFileHash, serverTimestamp);
                logRepository.save(log);

            } catch (DateTimeParseException e) {
                throw new IllegalArgumentException("날짜 형식이 올바르지 않습니다: " + logParts[0] + " " + logParts[1]);
            }
        }

        return "✅ 로그 저장 완료";
    }





    public String analyzeLogs(String deviceId, LocalDateTime startTime, LocalDateTime endTime) throws Exception {
        List<Log> logs = logRepository.findLogsWithinDuration(deviceId, startTime, endTime);
        logs.sort(Comparator.comparing(Log::getServerTimestamp));
        return generateReport(deviceId, logs, startTime, endTime);
    }


    private void addLogTable(Document document, String title, String[][] data, Color color) {

        document.add(new Paragraph(title)
                .setBold().setFontSize(14)
                .setMarginTop(15)
                .setMarginBottom(10));

        float[] columnWidths = {150f, 250f, 100f}; // 컬럼 너비 조정
        Table table = new Table(UnitValue.createPointArray(columnWidths));
        table.setWidth(UnitValue.createPercentValue(100)); // 전체 너비 조정

        // 헤더 스타일 적용
        String[] headers = {"Event Type", "Details", "Occurrence"};
        for (String header : headers) {
            Cell cell = new Cell().add(new Paragraph(header).setBold().setTextAlignment(TextAlignment.CENTER));
            cell.setBackgroundColor(new DeviceGray(0.85f)); // 연한 회색 배경
            cell.setBorder(Border.NO_BORDER);
            cell.setPadding(5);
            table.addHeaderCell(cell);
        }

        // 데이터에 대한 처리
        for (String[] row : data) {
            // 각 행의 "Event Type" (첫 번째 열)을 사용해 색상을 설정


            // "Event Type" 컬럼에 해당하는 셀 색상 적용
            Cell eventTypeCell = new Cell().add(new Paragraph(row[0]).setTextAlignment(TextAlignment.LEFT));
            eventTypeCell.setBackgroundColor(color);
            eventTypeCell.setBorder(Border.NO_BORDER);
            eventTypeCell.setPadding(5);
            table.addCell(eventTypeCell);

            // "Details" 컬럼
            Cell detailsCell = new Cell().add(new Paragraph(row[1]).setTextAlignment(TextAlignment.LEFT));
            detailsCell.setBackgroundColor(color);
            detailsCell.setBorder(Border.NO_BORDER);
            detailsCell.setPadding(5);
            table.addCell(detailsCell);

            // "Occurrence" 컬럼
            Cell occurrenceCell = new Cell().add(new Paragraph(row[2]).setTextAlignment(TextAlignment.CENTER));
            occurrenceCell.setBackgroundColor(color);
            occurrenceCell.setBorder(Border.NO_BORDER);
            occurrenceCell.setPadding(5);
            table.addCell(occurrenceCell);
        }

        // 테이블 추가
        document.add(table);
    }


    private String calculateEstimatedTimestamp(LocalDateTime serverTimestamp, LocalDateTime createdAt) {
        if (serverTimestamp != null && createdAt != null) {
            // serverTimestamp와 createdAt 사이의 차이 계산
            Duration duration = Duration.between(createdAt, serverTimestamp);

            // createdAt에 차이를 더한 보정 시간 계산
            LocalDateTime estimatedDateTime = createdAt.plus(duration);

            return estimatedDateTime.format(FORMATTER);
        } else if (serverTimestamp != null) {
            // serverTimestamp가 존재하면 그것을 그대로 사용
            return serverTimestamp.format(FORMATTER);
        } else if (createdAt != null) {
            // serverTimestamp가 없고 createdAt만 있다면 그것을 그대로 사용
            return createdAt.format(FORMATTER);
        }
        return "N/A"; // 두 값 모두 없으면 "N/A" 반환
    }

    private boolean isTimestampManipulated(Log log) {
        // 로그 메시지에 "Timestamp manipulation" 관련 키워드가 포함되어 있는지 확인
        return log.getMessage().contains("Anti-forensic event detected:") ||
                log.getMessage().contains("SystemClockTime: Setting time of day to sec=") ||
                log.getMessage().contains("Auto time setting enabled: false") ||
                log.getMessage().contains("Before System Time :");
    }



    public String generateReport(String deviceId, List<Log> logs, LocalDateTime startTime, LocalDateTime endTime) throws Exception {

// 로그 타입별로 색상 설정 (예시)
        Map<String, Color> logTypeColors = new HashMap<>();
        logTypeColors.put("AntiForensicLog", new DeviceRgb(255, 200, 245)); // Tomato 색 (Anti-Forensic)
        logTypeColors.put("CallLog", new DeviceRgb(103, 153, 255)); // SteelBlue 색 (Call Log)
        logTypeColors.put("BluetoothLog", new DeviceRgb(134, 229, 127)); // ForestGreen 색 (Bluetooth Log)
        logTypeColors.put("SMSLog", new DeviceRgb(250, 237, 125)); // Yellow 색 (SMS Log)


        String fileName = "custom_report_" + deviceId + ".pdf";
        String directoryPath = "reports";
        String filePath = directoryPath + "/" + fileName;

        Files.createDirectories(Paths.get(directoryPath));

        // 해시별 로그 그룹화
        Map<String, List<Log>> groupedLogs = logs.stream()
                .filter(log -> log.getCreatedAt().isAfter(startTime) && log.getCreatedAt().isBefore(endTime))
                .collect(Collectors.groupingBy(Log::getHash));

        StringBuilder hashValidationReport = new StringBuilder();
        boolean isAnyHashInvalid = false;

        // 각 해시 그룹별로 처리
        for (Map.Entry<String, List<Log>> entry : groupedLogs.entrySet()) {
            String expectedHash = entry.getKey();
            List<Log> logGroup = entry.getValue();

            // 그룹화된 로그들을 하나의 문자열로 합침
            StringBuilder logsContent = new StringBuilder();
            for (Log log : logGroup) {
                String logContent = log.getCreatedAt().format(FORMATTER) + " " + log.getMessage() + " ; serverTimestamp: " + log.getServerTimestamp().format(FORMATTER) + "\n";
                logsContent.append(logContent);
            }

            // 로그 내용을 파일로 저장
            String logFileName = "logs_" + expectedHash + ".txt";
            Path logFilePath = Paths.get(directoryPath, logFileName);
            Files.write(logFilePath, logsContent.toString().getBytes(StandardCharsets.UTF_8));

            // 해시 검증
            String calculatedFileHash = calculateFileHash(logFilePath);

            if (!expectedHash.equals(calculatedFileHash)) {
                isAnyHashInvalid = true;
                hashValidationReport.append(String.format("[Warning] Hash mismatch! Expected: %s, Found: %s\n", expectedHash, calculatedFileHash));
            }
        }

        String hashStatus = isAnyHashInvalid ? "[Warning] There is an issue with hash integrity, so log analysis cannot proceed.\n" :
                "[Success] Hash integrity verification completed. All logs have valid hash values.\n";
        hashValidationReport.append(hashStatus);

//        String timelineReport = isAnyHashInvalid ? "log analysis cannot proceed.\n" : generateTimelineReport(deviceId, logs);

        try (PdfWriter writer = new PdfWriter(new FileOutputStream(filePath));
             PdfDocument pdf = new PdfDocument(writer);
             Document document = new Document(pdf)) {

            // 기본 보고서 제목과 기간
            document.add(new Paragraph("📌 Device Log Report: " + deviceId)
                    .setBold().setFontSize(16)
                    .setMarginBottom(10));

            document.add(new Paragraph("⏳ Duration: " + startTime.format(FORMATTER) + " ~ " + endTime.format(FORMATTER))
                    .setFontSize(12)
                    .setMarginBottom(20));

            // 해시 검증 결과 추가
            document.add(new Paragraph(hashValidationReport.toString())
                    .setFontSize(12)
                    .setMarginBottom(20));

            // 해시 검증이 실패한 경우 표는 추가하지 않음
            if (!isAnyHashInvalid) {
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
                    row[2] = occurrence ? "O" : "";  // Set O if the keyword is found, X if not found
                }

                Color color = logTypeColors.getOrDefault("AntiForensicLog", new DeviceRgb(211, 211, 211)); // 기본값: 회색 (LightGray)
                addLogTable(document, "Anti-forensic Log", antiForensicData,color);


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
                    row[2] = occurrence ? "O" : "";  // Set O if the keyword is found, X if not found
                }
                color = logTypeColors.getOrDefault("CallLog", new DeviceRgb(211, 211, 211));
                addLogTable(document, "Call Log", callLogData,color);

                // SMS Log: Check if all three keywords are present
                String[][] smsLogData = {
                        {"send/receive SMS", "SMS, to/from, Message", ""}
                };
                for (String[] row : smsLogData) {
                    boolean occurrence = logs.stream().anyMatch(log -> log.getMessage().contains("SMS") &&
                            log.getMessage().contains("to/from") &&
                            log.getMessage().contains("Message"));
                    row[2] = occurrence ? "O" : "";  // Set O if all keywords are found, X if not found
                }
                color = logTypeColors.getOrDefault("SMSLog", new DeviceRgb(211, 211, 211));
                addLogTable(document, "SMS Log", smsLogData,color);

                // Bluetooth Log
                String[][] bluetoothLogData = {
                        {"connect Bluetooth", "Bluetooth connected to:", ""},
                        {"disconnect Bluetooth", "Bluetooth disconnected to:", ""},
                        {"start streaming", "A2DP streaming started on device:", ""},
                        {"stop streaming", "A2DP streaming stopped on device:", ""}
                };

                for (String[] row : bluetoothLogData) {
                    boolean occurrence = logs.stream().anyMatch(log -> log.getMessage().contains(row[1]));
                    row[2] = occurrence ? "O" : "";  // Set O if the keyword is found, X if not found
                }
                color = logTypeColors.getOrDefault("BluetoothLog", new DeviceRgb(211, 211, 211));
                addLogTable(document, "Bluetooth Log", bluetoothLogData,color);

                // "device timestamp", "message", "server timestamp" 표 추가
                document.add(new Paragraph("Reconstructing Timeline")
                        .setBold().setFontSize(14).setMarginTop(20));

                float[] columnWidths = {150f, 250f, 150f}; // 컬럼 너비 조정
                Table table = new Table(UnitValue.createPointArray(columnWidths));
                table.setWidth(UnitValue.createPercentValue(100)); // 전체 너비 조정


                // Device Timestamp 헤더 처리
                String[] headers = {"Device Timestamp", "Message", "Estimated Time Value"};
                for (String header : headers) {
                    Cell cell = new Cell().add(new Paragraph(header).setBold().setTextAlignment(TextAlignment.CENTER));
                    cell.setBackgroundColor(new DeviceGray(0.85f)); // 연한 회색 배경
                    cell.setBorder(Border.NO_BORDER);
                    cell.setPadding(5);
                    table.addHeaderCell(cell);
                }


// 데이터 추가
                List<LocalDateTime> manipulationTimes = new ArrayList<>();
                LocalDateTime lastManipulatedTimestamp = null;  // 마지막으로 조작된 타임스탬프

// 데이터 추가
                for (Log log : logs) {
                    // Device Timestamp 처리
                    List<String> deviceTimestamps = new ArrayList<>();
                    String createdAtStr = log.getCreatedAt().format(FORMATTER);
                    deviceTimestamps.add(createdAtStr); // 초기 createdAt 값 추가

                    LocalDateTime logTimestamp = log.getCreatedAt();

                    // 각 로그마다 타임스탬프 조작 시점 기록을 새로 초기화
                    if (isTimestampManipulated(log)) {
                        // calculateEstimatedTimestamp에서 반환된 문자열 형식 확인
                        String estimatedTimestamp = calculateEstimatedTimestamp(log.getServerTimestamp(), log.getCreatedAt());

                        // 예상된 타임스탬프가 "yyyy-MM-dd HH:mm:ss" 형식으로 되어 있는지 확인하고 파싱
                        try {
                            LocalDateTime parsedTimestamp = LocalDateTime.parse(estimatedTimestamp, DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
                            manipulationTimes.add(parsedTimestamp); // 타임스탬프 조작 시점 기록

                            // 마지막 조작 시점 업데이트
                            lastManipulatedTimestamp = parsedTimestamp;
                        } catch (DateTimeParseException e) {
                            // 파싱 실패 시 예외 처리
                            System.out.println("Error parsing timestamp: " + estimatedTimestamp);
                        }
                    }

                    // 이전에 발생한 타임스탬프 조작 시점까지 모든 타임스탬프를 화살표로 연결
                    if (lastManipulatedTimestamp != null) {


                        deviceTimestamps.add("-> " + calculateEstimatedTimestamp(log.getServerTimestamp(), lastManipulatedTimestamp));
                        // 화살표 추가
                    }

                    // Device Timestamp 셀 추가
                    Cell deviceTimestampCell = new Cell().add(new Paragraph(String.join(" ", deviceTimestamps)).setTextAlignment(TextAlignment.CENTER));
                    deviceTimestampCell.setBorder(Border.NO_BORDER).setPadding(5);
                    table.addCell(deviceTimestampCell);

                    // Message 처리
                    Cell messageCell = new Cell().add(new Paragraph(log.getMessage()).setTextAlignment(TextAlignment.LEFT));
                    messageCell.setBorder(Border.NO_BORDER).setPadding(5);
                    table.addCell(messageCell);

                    // Estimated Time Value 처리
                    String estimatedTimeValue = "-";  // 기본 값은 "-"
                    if ("AntiForensicLog".equals(log.getLogType()) && manipulationTimes.size() > 0) {
                        // Timestamp manipulation이 발생했을 때만 Estimated Time Value 계산
                        estimatedTimeValue = calculateEstimatedTimestamp(log.getServerTimestamp(), logTimestamp);
                    }

                    // Estimated Time Value 셀 추가
                    Cell estimatedTimevalueCell = new Cell().add(new Paragraph(estimatedTimeValue).setTextAlignment(TextAlignment.CENTER));
                    estimatedTimevalueCell.setBorder(Border.NO_BORDER).setPadding(5);
                    table.addCell(estimatedTimevalueCell);

                    // 로그 타입에 따라 셀 색상 지정
                    color = logTypeColors.getOrDefault(log.getLogType(), new DeviceRgb(211, 211, 211)); // 기본값: 회색 (LightGray)
                    deviceTimestampCell.setBackgroundColor(color);
                    messageCell.setBackgroundColor(color);
                    estimatedTimevalueCell.setBackgroundColor(color);


                }

// 표 추가
                document.add(table);


            }
            } catch (IOException e) {
            throw new IOException("PDF 생성 중 오류 발생. 실행중인 PDF를 종료시켜주세요", e);
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

//    public String generateTimelineReport(String deviceId, List<Log> logs) throws Exception {
//        StringBuilder report = new StringBuilder();
//
//        // 헤더 스타일 적용 (굵게 & 회색 배경)
//        report.append("\n\033[1;100m Timeline by Device Timestamp \033[0m\n\n");
//
//        // createdAt 기준 정렬
//        List<Log> createdAtSortedLogs = logs.stream()
//                .sorted(Comparator.comparing(Log::getCreatedAt))
//                .collect(Collectors.toList());
//
//        // 로그 출력
//        for (Log log : createdAtSortedLogs) {
//            report.append(String.format("%s %s\n",
//                    log.getCreatedAt().format(FORMATTER), log.getMessage()));
//        }
//
//        report.append("\n");
//
//        // serverTimestamp 기준 정렬
//        List<Log> serverTimestampSortedLogs = logs.stream()
//                .sorted(Comparator.comparing(Log::getServerTimestamp))
//                .collect(Collectors.toList());
//
//        report.append("\033[1;100m ⏳ Timeline by Server Timestamp \033[0m\n\n");
//
//        for (Log log : serverTimestampSortedLogs) {
//            report.append(String.format("%s %s\n",
//                    log.getServerTimestamp().format(FORMATTER), log.getMessage()));
//        }
//
//        return report.toString();
//    }
//



    private String calculateMessageHash(String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] textBytes = message.getBytes(StandardCharsets.UTF_8);
        digest.update(textBytes);
        byte[] hashBytes = digest.digest();
        return bytesToHex(hashBytes);
    }



    public void deleteAll() {
            logRepository.deleteAll();
    }
}
