package com.example.forensic.Service;


import com.example.forensic.Entity.Log;
import com.example.forensic.Repository.LogRepository;
import com.itextpdf.kernel.colors.DeviceGray;
import com.itextpdf.kernel.colors.Color;  // Color 클래스 import
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.layout.borders.Border;
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

    private static final ZoneId KST_ZONE = ZoneId.of("Asia/Seoul");
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    // 기존 정규식은 메시지를 group(1)에, serverTimestamp를 group(2)에 넣습니다
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

            String logFileHash = calculateFileHash(logFile);
            if (expectedHash != null && !logFileHash.equals(expectedHash)) {
                throw new IllegalArgumentException("로그 파일의 해시값이 hash.txt의 해시값과 일치하지 않습니다.");
            }

            // 로그 파일 읽기
            List<String> lines = new BufferedReader(new InputStreamReader(logFile.getInputStream(), StandardCharsets.UTF_8))
                    .lines()
                    .collect(Collectors.toList());

            // 디버깅: 파일에서 읽은 줄을 모두 출력
            System.out.println("===== 로그 파일 내용 =====");
            for (int i = 0; i < lines.size(); i++) {
                System.out.printf("[%02d] %s%n", i + 1, lines.get(i));
            }
            System.out.println("=========================");

            if (lines.isEmpty()) {
                throw new IllegalArgumentException("로그 파일이 비어 있습니다.");
            }

            // 중복 체크를 위한 Set 선언 (동기화 처리)
            Set<String> uniqueLogMessages = new HashSet<>();

            for (String line : lines) {
                String[] logParts = line.split(" ", 3);
                if (logParts.length < 3) continue;

                try {
                    String dateTimeString = logParts[0] + " " + logParts[1];
                    LocalDateTime createdAt = LocalDateTime.parse(dateTimeString, FORMATTER);
                    String message = logParts[2];

                    Matcher matcher = TIMESTAMP_PATTERN.matcher(message);
                    LocalDateTime serverTimestamp = null;
                    if (matcher.matches()) {
                        String mainMessage = matcher.group(1);
                        String serverTimestampString = matcher.group(2);
                        if (serverTimestampString != null) {
                            serverTimestamp = LocalDateTime.parse(serverTimestampString, FORMATTER);
                        }
                        message = mainMessage.trim();
                    }

                    // 중복 로그 메시지 확인 (Set을 사용하여 중복 방지)
                    String logKey = deviceId + createdAt + message + logType;

                    synchronized (uniqueLogMessages) {
                        if (uniqueLogMessages.contains(logKey)) {
                            System.out.println("중복된 로그 메시지 발견: " + message);
                            continue; // 중복된 로그는 저장하지 않음
                        }
                        uniqueLogMessages.add(logKey);
                    }

                    // 로그 저장
                    Log log = new Log(deviceId, createdAt, message, logType, logFileHash, serverTimestamp);
                    logRepository.save(log);
                    System.out.println("로그 저장: " + message);

                } catch (DateTimeParseException e) {
                    throw new IllegalArgumentException("날짜 형식이 올바르지 않습니다: " + logParts[0] + " " + logParts[1]);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }






    public String analyzeLog(String deviceId, LocalDateTime startTime, LocalDateTime endTime) {
        try {
            List<Log> logs = logRepository.findLogsWithinDuration(deviceId, startTime, endTime);
            logs.sort(Comparator.comparing(Log::getServerTimestamp));

            String result = generateReport(deviceId, logs, startTime, endTime);
            return result;
        } catch (Exception e) {
            return"❌ 보고서 생성 중 오류 발생: " + e.getMessage();
        }
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
            // "Occurrence" 값이 빈 값인 경우 해당 행을 건너뛰기
            if (row[2].trim().isEmpty()) {
                continue; // 빈 값이 있으면 해당 row는 추가하지 않음
            }

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
        // 로그 타입별 색상 설정
        Map<String, Color> logTypeColors = new HashMap<>();
        logTypeColors.put("AntiForensicLog", new DeviceRgb(255, 200, 245)); // Anti-Forensic 색상
        logTypeColors.put("CallLog", new DeviceRgb(103, 153, 255)); // Call Log 색상
        logTypeColors.put("BluetoothLog", new DeviceRgb(134, 229, 127)); // Bluetooth Log 색상
        logTypeColors.put("MessageLog", new DeviceRgb(250, 237, 125)); // Message Log 색상

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

        // 해시 그룹별로 처리
        for (Map.Entry<String, List<Log>> entry : groupedLogs.entrySet()) {
            String expectedHash = entry.getKey();
            List<Log> logGroup = entry.getValue();

            // 로그들을 하나의 문자열로 합침
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

        String hashStatus = isAnyHashInvalid ? "[Warning] Hash integrity issue, log analysis cannot proceed.\n" :
                "[Success] Hash integrity verification completed. All logs have valid hash values.\n";
        hashValidationReport.append(hashStatus);

        try (PdfWriter writer = new PdfWriter(new FileOutputStream(filePath));
             PdfDocument pdf = new PdfDocument(writer);
             Document document = new Document(pdf)) {

            // 보고서 제목 및 기간
            document.add(new Paragraph("📌 Device Log Report: " + deviceId)
                    .setBold().setFontSize(16)
                    .setMarginBottom(10));

            document.add(new Paragraph("⏳ Duration: " + startTime.format(FORMATTER) + " ~ " + endTime.format(FORMATTER))
                    .setFontSize(12)
                    .setMarginBottom(20));

            // 해시 검증 결과
            document.add(new Paragraph(hashValidationReport.toString())
                    .setFontSize(12)
                    .setMarginBottom(20));

            // 해시 검증이 실패하지 않은 경우에만 표 추가
            if (!isAnyHashInvalid) {
                // Anti-forensic Log 데이터 처리
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

                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

                for (String[] row : antiForensicData) {
                    String keyword = row[1].trim();

                    Optional<Log> matched = logs.stream()
                            .filter(log -> log.getMessage().toLowerCase().matches(".*" + Pattern.quote(keyword.toLowerCase()) + ".*"))
                            .findFirst();

                    if (matched.isPresent()) {
                        System.out.println("✅ Found match: " + matched.get().getMessage());
                        row[2] = formatter.format(matched.get().getCreatedAt());
                    } else {
                        System.out.println("❌ No match for: " + keyword);
                        row[2] = "";
                    }
                }

                // 테이블 추가 (배경색 적용 및 테두리 제거)
                addLogTableIfNotEmpty(document, "Anti-forensic Log", antiForensicData, logTypeColors.get("AntiForensicLog"));

                // 추가적으로 Call Log, Message Log 등 필요한 로그들에 대해서도 동일한 방식으로 처리
                // Call Log, Message Log, Bluetooth Log 등의 추가적인 데이터도 동일하게 처리하여 표에 추가할 수 있습니다.
// 'device timestamp', 'message', 'server timestamp' 표 추가
                document.add(new Paragraph("Reconstructing Timeline")
                        .setBold().setFontSize(14).setMarginTop(20));

                float[] columnWidths = {150f, 250f, 150f}; // 컬럼 너비 설정
                Table reconstructTable = new Table(UnitValue.createPointArray(columnWidths));
                reconstructTable.setWidth(UnitValue.createPercentValue(100));

// 회색 헤더 추가
                String[] headers = {"Device Timestamp", "Message", "Estimated Time Value"};
                for (String header : headers) {
                    Cell cell = new Cell().add(new Paragraph(header).setBold().setTextAlignment(TextAlignment.CENTER));
                    cell.setBackgroundColor(new DeviceGray(0.85f)); // 연한 회색 배경
                    cell.setBorder(Border.NO_BORDER);
                    cell.setPadding(5);
                    reconstructTable.addHeaderCell(cell);
                }

// 모든 로그를 한 테이블에 통합, 로그 타입별 배경색만 반영
                for (String logType : logTypeColors.keySet()) {
                    List<Log> filtered = logs.stream()
                            .filter(log -> logType.equals(log.getLogType()))
                            .collect(Collectors.toList());

                    Color bgColor = logTypeColors.get(logType);

                    for (Log log : filtered) {
                        reconstructTable.addCell(new Cell().add(new Paragraph(log.getCreatedAt().format(FORMATTER)))
                                .setBackgroundColor(bgColor)
                                .setBorder(Border.NO_BORDER)
                                .setPadding(5));

                        reconstructTable.addCell(new Cell().add(new Paragraph(log.getMessage()))
                                .setBackgroundColor(bgColor)
                                .setBorder(Border.NO_BORDER)
                                .setPadding(5));

                        String estimated = calculateEstimatedTimestamp(log.getServerTimestamp(), log.getCreatedAt());
                        String timeValue = log.getCreatedAt().format(FORMATTER) + " -> " + estimated;

                        reconstructTable.addCell(new Cell().add(new Paragraph(timeValue))
                                .setBackgroundColor(bgColor)
                                .setBorder(Border.NO_BORDER)
                                .setPadding(5));
                    }
                }

// 최종 테이블 추가
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

    public String generateTimelineReport(String deviceId, List<Log> logs) throws Exception {
        StringBuilder report = new StringBuilder();

        // 헤더 스타일 적용 (굵게 & 회색 배경)
        report.append("\n\033[1;100m Timeline by Device Timestamp \033[0m\n\n");

        // createdAt 기준 정렬
        List<Log> createdAtSortedLogs = logs.stream()
                .sorted(Comparator.comparing(Log::getCreatedAt))
                .collect(Collectors.toList());

        // 로그 출력
        for (Log log : createdAtSortedLogs) {
            report.append(String.format("%s %s\n",
                    log.getCreatedAt().format(FORMATTER), log.getMessage()));
        }

        report.append("\n");

        // serverTimestamp 기준 정렬
        List<Log> serverTimestampSortedLogs = logs.stream()
                .sorted(Comparator.comparing(Log::getServerTimestamp))
                .collect(Collectors.toList());

        report.append("\033[1;100m ⏳ Timeline by Server Timestamp \033[0m\n\n");

        for (Log log : serverTimestampSortedLogs) {
            report.append(String.format("%s %s\n",
                    log.getServerTimestamp().format(FORMATTER), log.getMessage()));
        }

        return report.toString();
    }




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
