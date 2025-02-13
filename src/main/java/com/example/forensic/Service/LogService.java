package com.example.forensic.Service;

import com.example.forensic.dto.LogRequest;
import com.example.forensic.Entity.Log;
import com.example.forensic.Repository.LogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class LogService {

    @Autowired
    private LogRepository logRepository;

    private static final ZoneId KST_ZONE = ZoneId.of("Asia/Seoul");
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public String appendLog(LogRequest logRequest) throws IOException {
        ZonedDateTime kstTime = ZonedDateTime.ofInstant(Instant.now(), KST_ZONE);
        LocalDateTime serverTimestamp = kstTime.toLocalDateTime();

        // 로그 엔티티 생성
        Log log = new Log(
                logRequest.getDeviceId(),
                logRequest.getCreatedAt(),
                logRequest.getMessage(),
                logRequest.getLogType(),
                logRequest.getFileHash(),
                serverTimestamp
        );

        try {
            // DB에 로그 저장 시 예외 처리 (DB 연결 실패 감지)
            logRepository.save(log);
        } catch (Exception e) {
            // DB 연결 실패 시 파일 입출력 중지
            throw new IOException("DB connection failed, cannot write to log file.", e);
        }

        // 디렉토리 생성 및 로그 파일 작성 (/log/{logType}/{deviceId}.txt)
        Path dirPath = Paths.get("log", logRequest.getLogType()); // logType 하위에 디렉토리 생성
        Files.createDirectories(dirPath);
        Path logFile = dirPath.resolve(logRequest.getDeviceId() + ".txt"); // deviceId를 파일 이름으로 사용

        // 첫 번째 줄: {createdAt}, {message}
        // 두 번째 줄: - [INFO] {createdAt} serverTimestamp : {serverTimestamp}
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(logFile,
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.APPEND))) {
            // 첫 번째 줄
            writer.printf("%s %s\n",
                    logRequest.getCreatedAt().format(FORMATTER),  // createdAt
                    logRequest.getMessage());                       // message

            // 두 번째 줄
            writer.printf("- [INFO] %s serverTimestamp : %s\n",
                    logRequest.getCreatedAt().format(FORMATTER),  // createdAt
                    serverTimestamp.format(FORMATTER));           // serverTimestamp
        }

        return serverTimestamp.format(FORMATTER);
    }



    public String readLog(String deviceId, String logType) {
        // 공통 logs 컬렉션 조회
        List<Log> logs = logRepository.findByDeviceIdAndLogType(deviceId, logType);
        return logs.toString();
    }
}




