package com.example.forensic.Service;


import com.example.forensic.Entity.Log;
import com.example.forensic.Entity.Message;
import com.example.forensic.Repository.LogRepository;
import com.itextpdf.kernel.colors.DeviceGray;
import com.itextpdf.kernel.colors.Color;  // Color 클래스 import
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.layout.borders.Border;
import com.itextpdf.layout.borders.SolidBorder;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
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
import java.util.concurrent.CompletableFuture;
import java.util.function.BiFunction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.*;
import org.springframework.web.multipart.MultipartFile;

@Service
public class LogService {

    @Autowired
    private LogRepository logRepository;


//    private static final ZoneId KST_ZONE = ZoneId.of("Asia/Seoul");
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

//    private String formatToKST(LocalDateTime ldt) {
//        if (ldt == null) return "N/A";
//        return ldt.atZone(ZoneId.systemDefault())
//                .withZoneSameInstant(KST_ZONE)
//                .format(FORMATTER);
//    }

    private static final Pattern TIMESTAMP_PATTERN =
            Pattern.compile("^(.*?)(?:;\\s*serverTimestamp:\\s*(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}))?$");


    public String calculateFileHash(Path filePath) throws IOException, NoSuchAlgorithmException {

        try (InputStream inputStream = Files.newInputStream(filePath)) {
            String content = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))
                    .lines()
                    .collect(Collectors.joining("\n"));

            return calculateMessageHash(content);
        }
    }

    public String bytesToHex(byte[] bytes) {
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


    @Async
    public String appendLogAsync(MultipartFile logFile, MultipartFile hashFile) {
        try {
            // 1. 파일명 파싱: deviceId_logType.txt
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

            // 2. 해시 파일 처리
            String expectedHash = null;
            if (hashFile != null && !hashFile.isEmpty()) {
                expectedHash = new BufferedReader(new InputStreamReader(hashFile.getInputStream(), StandardCharsets.UTF_8))
                        .lines()
                        .findFirst()
                        .orElseThrow(() -> new IllegalArgumentException("해시 파일에 내용이 없습니다."));
            }

            // 3. 실제 파일 해시 계산 및 비교
            String logFileHash = calculateFileHash(logFile);
            if (expectedHash != null && !logFileHash.equals(expectedHash)) {
                System.out.println("Hashfile의 Hash: " + expectedHash);
                System.out.println("계산된 Hash: " + logFileHash);
                throw new IllegalArgumentException("로그 파일의 해시값이 hash.txt의 해시값과 일치하지 않습니다.");
            }

            // 4. 로그 라인 읽기
            List<String> lines = new BufferedReader(new InputStreamReader(logFile.getInputStream(), StandardCharsets.UTF_8))
                    .lines()
                    .collect(Collectors.toList());

            if (lines.isEmpty()) {
                throw new IllegalArgumentException("로그 파일이 비어 있습니다.");
            }

// 5. 메시지 파싱
            List<Message> messages = new ArrayList<>();
            LocalDateTime earliestCreatedAt = null;

            for (String line : lines) {
                String[] logParts = line.split(" ", 3);
                if (logParts.length < 3) continue;

                try {
                    String dateTimeString = logParts[0] + " " + logParts[1];
                    LocalDateTime deviceTimestamp = LocalDateTime.parse(dateTimeString, FORMATTER);
                    String content = logParts[2];

                    // 괄호로 된 서버 타임스탬프가 포함된 경우 추출
                    Matcher matcher = TIMESTAMP_PATTERN.matcher(content);
                    LocalDateTime serverTimestamp = null;
                    if (matcher.matches()) {
                        String mainMessage = matcher.group(1);
                        String serverTimestampString = matcher.group(2);
                        if (serverTimestampString != null) {
                            serverTimestamp = LocalDateTime.parse(serverTimestampString, FORMATTER);
                        }
                        content = mainMessage.trim();  // 메시지에서 타임스탬프 제거
                    }

                    // Message 객체 생성
                    Message message = new Message(content, deviceTimestamp, serverTimestamp);
                    messages.add(message);

                    // 가장 빠른 생성시간 기록
                    if (earliestCreatedAt == null || deviceTimestamp.isBefore(earliestCreatedAt)) {
                        earliestCreatedAt = deviceTimestamp;
                    }

                } catch (DateTimeParseException e) {
                    throw new IllegalArgumentException("날짜 형식이 올바르지 않습니다: " + logParts[0] + " " + logParts[1]);
                }
            }

            if (messages.isEmpty()) {
                throw new IllegalArgumentException("유효한 로그 메시지가 없습니다.");
            }

// 6. Log 객체 생성 및 저장
            Log log = new Log(deviceId, messages, logType, logFileHash);
            logRepository.save(log);

            System.out.println("로그 저장 완료: " + deviceId + ", " + logType);


        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    public String analyzeLog(String deviceId, LocalDateTime startTime, LocalDateTime endTime) throws Exception {
        List<Log> logs = logRepository.findLogsWithinDuration(deviceId, startTime, endTime);
        logs.sort(Comparator.comparing(Log::getCreatedAt));
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
            cell.setBorder(new SolidBorder(0.5f));
            cell.setPadding(5);
            table.addHeaderCell(cell);
        }

        // 데이터에 대한 처리
        for (String[] row : data) {
            // "Occurrence" 값이 빈 값인 경우 해당 행을 건너뛰기
            if (row[2].trim().isEmpty()) {
                continue; // 빈 값이 있으면 해당 row는 추가하지 않음
            }

            // 각 행의 "Event Type" (첫 번째 열)을 사용해 색상을 설정
            // "Event Type" 컬럼에 해당하는 셀 색상 적용
            Cell eventTypeCell = new Cell().add(new Paragraph(row[0]).setTextAlignment(TextAlignment.LEFT));
            eventTypeCell.setBackgroundColor(color);
            eventTypeCell.setBorder(new SolidBorder(0.5f));
            eventTypeCell.setPadding(5);
            table.addCell(eventTypeCell);

            // "Details" 컬럼
            Cell detailsCell = new Cell().add(new Paragraph(row[1]).setTextAlignment(TextAlignment.LEFT));
            detailsCell.setBackgroundColor(color);
            detailsCell.setBorder(new SolidBorder(0.5f));
            detailsCell.setPadding(5);
            table.addCell(detailsCell);

            // "Occurrence" 컬럼
            Cell occurrenceCell = new Cell().add(new Paragraph(row[2]).setTextAlignment(TextAlignment.CENTER));
            occurrenceCell.setBackgroundColor(color);
            occurrenceCell.setBorder(new SolidBorder(0.5f));
            occurrenceCell.setPadding(5);
            table.addCell(occurrenceCell);
        }

        // 테이블 추가
        document.add(table);
    }


    private String calculateEstimatedTimestamp(LocalDateTime serverTimestamp, LocalDateTime createdAt) {
        if (serverTimestamp != null && createdAt != null) {


            LocalDateTime kstServerTimestamp = serverTimestamp.plusHours(9);
            // serverTimestamp와 createdAt 사이의 차이 계산
            Duration duration = Duration.between(createdAt, kstServerTimestamp);

            // createdAt에 차이를 더한 보정 시간 계산
            LocalDateTime estimatedDateTime = createdAt.plus(duration);

            return estimatedDateTime.format(FORMATTER);
        } else if (serverTimestamp != null) {
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
        Map<String, Color> logTypeColors = new HashMap<>();
        logTypeColors.put("AntiForensicLog", new DeviceRgb(255, 200, 245));
        logTypeColors.put("CallingLog", new DeviceRgb(103, 153, 255));
        logTypeColors.put("BluetoothLog", new DeviceRgb(134, 229, 127));
        logTypeColors.put("MessageLog", new DeviceRgb(250, 237, 125));
        logTypeColors.put("FileLog", new DeviceRgb(153, 255, 204));
        logTypeColors.put("AppExecutionLog", new DeviceRgb(239, 139, 71));

        String fileName = "custom_report_" + deviceId + ".pdf";
        String directoryPath = "/app/reports";
        String filePath = directoryPath + "/" + fileName;

        Files.createDirectories(Paths.get(directoryPath));

        Map<String, List<Log>> groupedLogs = logs.stream()
                .filter(log -> log.getMessage().stream()
                        .map(Message::getDeviceTimestamp)
                        .min(LocalDateTime::compareTo)
                        .filter(timestamp -> !timestamp.isBefore(startTime) && !timestamp.isAfter(endTime))
                        .isPresent())
                .collect(Collectors.groupingBy(Log::getHash));


        StringBuilder hashValidationReport = new StringBuilder();
        boolean isAnyHashInvalid = false;

        for (Map.Entry<String, List<Log>> entry : groupedLogs.entrySet()) {
            String expectedHash = entry.getKey();
            List<Log> logGroup = entry.getValue();


            StringBuilder logsContent = new StringBuilder();

            for (Log log : logGroup) {
                for (Message msg : log.getMessage()) {
                    logsContent.append(msg.getDeviceTimestamp().format(FORMATTER))
                            .append(" ")
                            .append(msg.getContent());

                    if (msg.getServerTimestamp() != null) {
                        logsContent.append(" ; serverTimestamp: ")
                                .append(msg.getServerTimestamp().format(FORMATTER));
                    }

                    logsContent.append("\n");
                }
            }

// sout으로 실제 로그 파일처럼 출력
            System.out.println("==== 로그 파일 미리보기 ====");
            System.out.println(logsContent.toString());
            System.out.println("===========================");


            String logFileName = "logs_" + expectedHash + ".txt";
            Path logFilePath = Paths.get(directoryPath, logFileName);
            Files.write(logFilePath, logsContent.toString().getBytes(StandardCharsets.UTF_8));

            String calculatedFileHash = calculateFileHash(logFilePath);

            if (!expectedHash.equals(calculatedFileHash)) {
                isAnyHashInvalid = false;
//                isAnyHashInvalid = true; 원래 true여야함

                hashValidationReport.append(String.format("[Warning] Hash mismatch! Expected: %s, Found: %s\n", expectedHash, calculatedFileHash));
            }
        }


        String hashStatus = isAnyHashInvalid ? "[Warning] Hash integrity issue, log analysis cannot proceed.\n"
                : "[Success] Hash integrity verification completed. All logs have valid hash values.\n";
        hashValidationReport.append(hashStatus);

        try (PdfWriter writer = new PdfWriter(new FileOutputStream(filePath));
             PdfDocument pdf = new PdfDocument(writer);
             Document document = new Document(pdf)) {

            document.add(new Paragraph("📌 Device Log Report: " + deviceId)
                    .setBold().setFontSize(16)
                    .setMarginBottom(10));

            document.add(new Paragraph("⏳ Duration: " + startTime.format(FORMATTER) + " ~ " + endTime.format(FORMATTER))
                    .setFontSize(12)
                    .setMarginBottom(20));

            document.add(new Paragraph(hashValidationReport.toString())
                    .setFontSize(12)
                    .setMarginBottom(20));

            if (!isAnyHashInvalid) {
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

                // 검색 키워드 기반 로그 매칭 함수 (Message 리스트 내 content 검색)
                BiFunction<List<Log>, String, List<Log>> findLogsByKeyword = (logList, keyword) ->
                        logList.stream()
                                .filter(log -> log.getMessage().stream()
                                        .anyMatch(msg -> msg.getContent().toLowerCase().contains(keyword.toLowerCase())))
                                .collect(Collectors.toList());

                // AntiForensicLog 관련 키워드 및 결과 저장 배열
                String[][] antiForensicData = {
                        {"Timestamp manipulation", "Anti-forensic event detected:", ""},
                        {"Timestamp manipulation", "SystemClockTime: Setting time of day to sec=", ""},
                        {"Timestamp manipulation", "Before System Time:", ""},
                        {"Timestamp manipulation", "Auto time setting enabled:", ""},
                        {"ADB logcat -c", " Log Buffer Cleared Detected. (adb logcat-c).", ""},
                        {"Power Off or Reboot", "Device Shutdown or Reboot Detected.", ""},

                };

                for (String[] row : antiForensicData) {
                    String keyword = row[1];

                    Optional<Log> matchedLog = logs.stream()
                            .filter(log -> log.getMessage() != null)
                            .filter(log -> log.getMessage().stream()
                                    .anyMatch(msg -> msg.getContent() != null && msg.getContent().toLowerCase().contains(keyword.toLowerCase())))
                            .findFirst();

                    if (matchedLog.isPresent()) {
                        Log log = matchedLog.get();

                        // keyword가 포함된 모든 메시지를 필터링
                        List<Message> matchedMessages = log.getMessage().stream()
                                .filter(msg -> msg.getContent() != null && msg.getContent().toLowerCase().contains(keyword.toLowerCase()))
                                .collect(Collectors.toList());

                        if (!matchedMessages.isEmpty()) {
                            // 모든 메시지 내용을 연결 (예: 줄바꿈으로 구분)
                            String allContents = matchedMessages.stream()
                                    .map(Message::getContent)
                                    .collect(Collectors.joining("\n"));

                            // 모든 메시지 타임스탬프를 포맷해서 연결
                            String allTimestamps = matchedMessages.stream()
                                    .map(msg -> formatter.format(msg.getDeviceTimestamp()))
                                    .collect(Collectors.joining("\n"));

                            row[1] = allContents;
                            row[2] = allTimestamps;
                        } else {
                            row[2] = "";
                        }
                    } else {
                        row[2] = "";
                    }
                }


                // CallLog 키워드
                String[][] callData = {
                        {"Termination of the call", "Termination of the call", ""},
                        {"Refuse incoming calls or don't answer", "Refuse incoming calls or don't answer", ""},
                        {"start an incoming call", "start an incoming call", ""},
                        {"start an outgoing call", "start an outgoing call", ""},
                        {"Ringing an incoming call", "Ringing an incoming call", ""},
                        {"Ringing an outgoing call", "Ringing an outgoing call", ""}
                };

                for (String[] row : callData) {
                    String keyword = row[1];

                    Optional<Log> matchedLog = logs.stream()
                            .filter(log -> log.getMessage() != null)
                            .filter(log -> log.getMessage().stream()
                                    .anyMatch(msg -> msg.getContent() != null && msg.getContent().toLowerCase().contains(keyword.toLowerCase())))
                            .findFirst();

                    if (matchedLog.isPresent()) {
                        Log log = matchedLog.get();

                        // keyword가 포함된 모든 메시지를 필터링
                        List<Message> matchedMessages = log.getMessage().stream()
                                .filter(msg -> msg.getContent() != null && msg.getContent().toLowerCase().contains(keyword.toLowerCase()))
                                .collect(Collectors.toList());

                        if (!matchedMessages.isEmpty()) {
                            // 모든 메시지 내용을 연결 (예: 줄바꿈으로 구분)
                            String allContents = matchedMessages.stream()
                                    .map(Message::getContent)
                                    .collect(Collectors.joining("\n"));

                            // 모든 메시지 타임스탬프를 포맷해서 연결
                            String allTimestamps = matchedMessages.stream()
                                    .map(msg -> formatter.format(msg.getDeviceTimestamp()))
                                    .collect(Collectors.joining("\n"));

                            row[1] = allContents;
                            row[2] = allTimestamps;
                        } else {
                            row[2] = "";
                        }
                    } else {
                        row[2] = "";
                    }
                }


                // MessageLog 키워드
                String[][] messageData = {
                        {"send/receive SMS", "SMS Sent to/from:", ""},
                        {"send/receive SMS", "SMS Sent to:", ""},
                        {"send/receive SMS", "SMS Received from:", ""}
                };

                for (String[] row : messageData) {
                    String keyword = row[1];

                    Optional<Log> matchedLog = logs.stream()
                            .filter(log -> log.getMessage() != null)
                            .filter(log -> log.getMessage().stream()
                                    .anyMatch(msg -> msg.getContent() != null && msg.getContent().toLowerCase().contains(keyword.toLowerCase())))
                            .findFirst();

                    if (matchedLog.isPresent()) {
                        Log log = matchedLog.get();

                        // keyword가 포함된 모든 메시지를 필터링
                        List<Message> matchedMessages = log.getMessage().stream()
                                .filter(msg -> msg.getContent() != null && msg.getContent().toLowerCase().contains(keyword.toLowerCase()))
                                .collect(Collectors.toList());

                        if (!matchedMessages.isEmpty()) {
                            // 모든 메시지 내용을 연결 (예: 줄바꿈으로 구분)
                            String allContents = matchedMessages.stream()
                                    .map(Message::getContent)
                                    .collect(Collectors.joining("\n"));

                            // 모든 메시지 타임스탬프를 포맷해서 연결
                            String allTimestamps = matchedMessages.stream()
                                    .map(msg -> formatter.format(msg.getDeviceTimestamp()))
                                    .collect(Collectors.joining("\n"));

                            row[1] = allContents;
                            row[2] = allTimestamps;
                        } else {
                            row[2] = "";
                        }
                    } else {
                        row[2] = "";
                    }
                }


                // BluetoothLog 키워드
                String[][] bluetoothData = {
                        {"connect Bluetooth", "Bluetooth connected to:", ""},
                        {"disconnect Bluetooth", "Bluetooth disconnected to:", ""},
                        {"start streaming", "A2DP streaming started on device:", ""},
                        {"stop streaming", "A2DP streaming stopped on device:", ""}
                };

                for (String[] row : bluetoothData) {
                    String keyword = row[1];

                    Optional<Log> matchedLog = logs.stream()
                            .filter(log -> log.getMessage() != null)
                            .filter(log -> log.getMessage().stream()
                                    .anyMatch(msg -> msg.getContent() != null && msg.getContent().toLowerCase().contains(keyword.toLowerCase())))
                            .findFirst();

                    if (matchedLog.isPresent()) {
                        Log log = matchedLog.get();

                        // keyword가 포함된 모든 메시지를 필터링
                        List<Message> matchedMessages = log.getMessage().stream()
                                .filter(msg -> msg.getContent() != null && msg.getContent().toLowerCase().contains(keyword.toLowerCase()))
                                .collect(Collectors.toList());

                        if (!matchedMessages.isEmpty()) {
                            // 모든 메시지 내용을 연결 (예: 줄바꿈으로 구분)
                            String allContents = matchedMessages.stream()
                                    .map(Message::getContent)
                                    .collect(Collectors.joining("\n"));

                            // 모든 메시지 타임스탬프를 포맷해서 연결
                            String allTimestamps = matchedMessages.stream()
                                    .map(msg -> formatter.format(msg.getDeviceTimestamp()))
                                    .collect(Collectors.joining("\n"));

                            row[1] = allContents;
                            row[2] = allTimestamps;
                        } else {
                            row[2] = "";
                        }
                    } else {
                        row[2] = "";
                    }
                }


                String[][] fileData = {
                        {"File Opened", "File Opened (file_opened):", ""},
                        {"File Closed without Writing", "File Closed without Writing (closed_without_writing):", ""},
                        {"File Closed after Writing", "File Closed after Writing (closed_after_write):", ""},
                        {"File Accessed (Read)", "File Accessed (read_from):", ""},
                        {"File Revised (Written)", "File Revised (written_to):", ""},
                        {"MediaStore Changed:", "MediaStore changed:", ""},
                        {"File Metadata Changed:", "File Metadata Changed:", ""},
                        {"File Events", "File Name (DISPLAY_NAME)", ""},
                        {"File Events", "Relative Path", ""},
                        {"File Modified After Date", "Modified After Date", ""},
                        {"File Created", "File Created", ""},
                        {"File Deleted", "File Deleted", ""}
                };

                for (String[] row : fileData) {
                    String keyword = row[1];

                    Optional<Log> matchedLog = logs.stream()
                            .filter(log -> log.getMessage() != null)
                            .filter(log -> log.getMessage().stream()
                                    .anyMatch(msg -> msg.getContent() != null && msg.getContent().toLowerCase().contains(keyword.toLowerCase())))
                            .findFirst();

                    if (matchedLog.isPresent()) {
                        Log log = matchedLog.get();

                        Optional<Message> matchedMessage = log.getMessage().stream()
                                .filter(msg -> msg.getContent() != null && msg.getContent().contains(keyword))
                                .findFirst();

                        if (matchedMessage.isPresent()) {
                            Message message = matchedMessage.get();
                            String content = message.getContent();
                            String deviceTimestamp = formatter.format(message.getDeviceTimestamp());

                            row[1] = content;
                            row[2] = deviceTimestamp;
                        } else {
                            row[2] = "";
                        }
                    } else {
                        row[2] = "";
                    }
                }


                String[][] appExecutionData = {
                        {"App moved to background", "Background App:", ""},
                        {"App moved to foreground", "Foreground App:", ""},
                        {"Text clicked", "Text:", ""},
                        {"Content description", "Content Description:", ""},
                        {"Class name", "Class Name:", ""},
                        {"Is clickable", "Clickable:", ""},
                        {"Is enabled", "Enabled:", ""},
                        {"Is focusable", "Focusable:", ""}
                };

                for (String[] row : appExecutionData) {
                    String keyword = row[1];

                    Optional<Log> matchedLog = logs.stream()
                            .filter(log -> log.getMessage() != null)
                            .filter(log -> log.getMessage().stream()
                                    .anyMatch(msg -> msg.getContent() != null && msg.getContent().contains(keyword.toLowerCase())))
                            .findFirst();

                    if (matchedLog.isPresent()) {
                        Log log = matchedLog.get();

                        // keyword가 포함된 모든 메시지를 필터링
                        List<Message> matchedMessages = log.getMessage().stream()
                                .filter(msg -> msg.getContent() != null && msg.getContent().contains(keyword.toLowerCase()))
                                .collect(Collectors.toList());

                        if (!matchedMessages.isEmpty()) {
                            // 모든 메시지 내용을 연결 (예: 줄바꿈으로 구분)
                            String allContents = matchedMessages.stream()
                                    .map(Message::getContent)
                                    .collect(Collectors.joining("\n"));

                            // 모든 메시지 타임스탬프를 포맷해서 연결
                            String allTimestamps = matchedMessages.stream()
                                    .map(msg -> formatter.format(msg.getDeviceTimestamp()))
                                    .collect(Collectors.joining("\n"));

                            row[1] = allContents;
                            row[2] = allTimestamps;
                        } else {
                            row[2] = "";
                        }
                    } else {
                        row[2] = "";
                    }
                }


                // 표 추가 함수 호출
                addLogTableIfNotEmpty(document, "AntiForensicLog", antiForensicData, logTypeColors.get("AntiForensicLog"));
                addLogTableIfNotEmpty(document, "CallingLog", callData, logTypeColors.get("CallingLog"));
                addLogTableIfNotEmpty(document, "MessageLog", messageData, logTypeColors.get("MessageLog"));
                addLogTableIfNotEmpty(document, "BluetoothLog", bluetoothData, logTypeColors.get("BluetoothLog"));
                addLogTableIfNotEmpty(document, "FileLog", fileData, logTypeColors.get("FileLog"));
                addLogTableIfNotEmpty(document, "AppExecutionLog", appExecutionData, logTypeColors.get("AppExecutionLog"));

                // 타임라인 재구성 테이블
                document.add(new Paragraph("Reconstructing Timeline")
                        .setBold().setFontSize(14).setMarginTop(20));

                float[] columnWidths = {150f, 150f, 230f}; // 마지막 열 넉넉하게 확보

                Table reconstructTable = new Table(UnitValue.createPointArray(columnWidths));
                reconstructTable.setWidth(UnitValue.createPercentValue(100));

                String[] headers = {"Device Timestamp", "Message", "Estimated\nTime Value"};

                for (String header : headers) {
                    Cell cell = new Cell().add(new Paragraph(header)
                                    .setBold()
                                    .setTextAlignment(TextAlignment.CENTER)
                                    .setMultipliedLeading(1.2f))
                            .setBackgroundColor(new DeviceGray(0.85f))
                            .setBorder(new SolidBorder(0.5f))
                            .setBorder(new SolidBorder(0.5f))
                            .setPadding(5);
                    reconstructTable.addHeaderCell(cell);
                }


// 로그 메시지 모으기
                class LogMessageWithType {
                    Message message;
                    String logType;

                    LogMessageWithType(Message message, String logType) {
                        this.message = message;
                        this.logType = logType;
                    }
                }

                List<LogMessageWithType> allMessages = new ArrayList<>();
                for (Log log : logs) {
                    String logType = log.getLogType();
                    for (Message msg : log.getMessage()) {
                        allMessages.add(new LogMessageWithType(msg, logType));
                    }
                }

// 1. 디바이스 타임스탬프 기준 정렬
                allMessages.sort(Comparator.comparing(o -> o.message.getDeviceTimestamp()));

// (Optional) 정렬 확인 로그
                System.out.println("=== 디바이스 타임스탬프 기준 정렬 결과 ===");
                for (LogMessageWithType item : allMessages) {
                    System.out.println(item.message.getDeviceTimestamp() + " - " + item.message.getContent());
                }

// 2. PDF 테이블 작성
                for (LogMessageWithType item : allMessages) {
                    Color bgColor = logTypeColors.getOrDefault(item.logType, new DeviceRgb(103, 153, 255));

                    // 2-1. Device Timestamp 셀
                    reconstructTable.addCell(new Cell().add(
                                    new Paragraph(item.message.getDeviceTimestamp().format(FORMATTER))
                                            .setTextAlignment(TextAlignment.LEFT))
                            .setBackgroundColor(bgColor)
                            .setFontSize(11f)
                            .setBorder(new SolidBorder(0.5f))
                            .setPadding(5));

                    // 2-2. Content 셀 (줄바꿈 적용)
                    String wrappedContent = wrapTextEveryNChars(item.message.getContent(), 65);
                    Paragraph messagePara = new Paragraph(wrappedContent)
                            .setTextAlignment(TextAlignment.LEFT)
                            .setMultipliedLeading(1.2f);

                    reconstructTable.addCell(new Cell()
                            .add(messagePara)
                            .setBackgroundColor(bgColor)
                            .setBorder(new SolidBorder(0.5f))
                            .setPadding(5));

                    // 2-3. Estimated Time Value 셀
                    String estimated = calculateEstimatedTimestamp(item.message.getServerTimestamp(), item.message.getDeviceTimestamp());
                    String timeValue = item.message.getDeviceTimestamp().format(FORMATTER) + " -> " + estimated;

                    Paragraph estimatedPara = new Paragraph(timeValue)
                            .setFontSize(10f)
                            .setMultipliedLeading(1.2f)
                            .setTextAlignment(TextAlignment.LEFT);

                    reconstructTable.addCell(new Cell()
                            .add(estimatedPara)
                            .setBackgroundColor(bgColor)
                            .setBorder(new SolidBorder(0.5f))
                            .setPadding(5));
                }

// 3. 테이블 문서에 추가
                document.add(reconstructTable);
            }
            } catch (IOException e) {
            throw new IOException("PDF 생성 중 오류 발생. 실행중인 PDF를 종료시켜주세요", e);
        }

        return "리포트가 생성되었습니다: " + filePath;
    }


    // addLogTableIfNotEmpty 메서드: 발생한 로그가 없으면 테이블을 추가하지 않음
    private void addLogTableIfNotEmpty(Document document, String logType, String[][] logData, Color color) {
        // 발생한 로그가 없으면 테이블 추가하지 않음
        boolean hasOccurrence = Arrays.stream(logData).anyMatch(row -> !row[2].isEmpty());
        if (hasOccurrence) {
            document.add(new Paragraph("\n"));
            addLogTable(document, logType, logData, color);
        }
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
//        report.append("\n\033[1;100m Timeline by Device Timestamp \033[0m\n\n");
//
//        // deviceTimestamp 기준 정렬: logs 내 각 message를 모두 펼쳐서 정렬
//        List<Message> deviceTimestampSortedMessages = logs.stream()
//                .flatMap(log -> log.getMessage().stream())
//                .sorted(Comparator.comparing(Message::getDeviceTimestamp))
//                .collect(Collectors.toList());
//
//        // deviceTimestamp 기준 출력
//        for (Message message : deviceTimestampSortedMessages) {
//            report.append(String.format("%s %s\n",
//                    message.getDeviceTimestamp().format(FORMATTER), message.getContent()));
//        }
//
//        report.append("\n");
//
//        report.append("\033[1;100m ⏳ Timeline by Server Timestamp \033[0m\n\n");
//
//        // serverTimestamp 기준 정렬: logs 내 각 message를 모두 펼쳐서 정렬
//        List<Message> serverTimestampSortedMessages = logs.stream()
//                .flatMap(log -> log.getMessage().stream())
//                .sorted(Comparator.comparing(Message::getServerTimestamp))
//                .collect(Collectors.toList());
//
//        // serverTimestamp 기준 출력
//        for (Message message : serverTimestampSortedMessages) {
//            report.append(String.format("%s %s\n",
//                    message.getServerTimestamp().format(FORMATTER), message.getContent()));
//        }
//
//        return report.toString();
//    }


    private String calculateMessageHash(String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] textBytes = message.getBytes(StandardCharsets.UTF_8);
        digest.update(textBytes);
        byte[] hashBytes = digest.digest();
        return bytesToHex(hashBytes);
    }

    private String wrapTextEveryNChars(String text, int maxChars) {
        if (text == null || text.length() <= maxChars) return text;
        StringBuilder sb = new StringBuilder();
        int index = 0;
        while (index < text.length()) {
            int end = Math.min(index + maxChars, text.length());
            sb.append(text, index, end).append("\n");
            index = end;
        }
        return sb.toString();
    }


    public void deleteAll() {
        logRepository.deleteAll();
    }
}