package com.example.forensic.Service;

import com.example.forensic.dto.LogRequest;
import com.example.forensic.Entity.Log;
import com.example.forensic.Repository.LogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

@Service
public class LogService {

    @Autowired
    private LogRepository logRepository;

    private static final ZoneId KST_ZONE = ZoneId.of("Asia/Seoul");
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");


    // 로그를 deviceId별로 서브 컬렉션에 저장
    public String appendLog(LogRequest logRequest) {

        // deviceId를 컬렉션 이름으로 사용
        String collectionName = logRequest.getDeviceId() + "_logs";



        // 로그 데이터를 Log 객체로 변환
        Log log = new Log(
                logRequest.getDeviceId(),
                logRequest.getSequenceNumber(),
                logRequest.getTimestamp(),
                logRequest.getMessage(),
                logRequest.getLogType()
        );

        // 해당 deviceId 컬렉션에 로그 저장
        logRepository.save(log, collectionName);  // LogRepository에서 collectionName을 지정할 수 있어야 함

        ZonedDateTime kstTime = ZonedDateTime.ofInstant(Instant.now(), KST_ZONE);
        return kstTime.format(FORMATTER);

    }

    // 로그를 조회하는 메서드 (deviceId에 맞는 컬렉션에서 조회)
    public String readLog(String deviceId, String logType) {
        String collectionName = deviceId + "_logs";  // deviceId별로 컬렉션을 선택

        // deviceId 및 logType을 기준으로 로그 조회
        List<Log> logs = logRepository.findByDeviceIdAndLogType(deviceId, logType, collectionName);

        // 조회된 로그를 반환
        return logs.toString();  // 로그 내용 반환 (실제 구현 시 로그 내용 포맷에 맞게 처리)
    }
}
