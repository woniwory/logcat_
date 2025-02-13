package com.example.forensic.Entity;

import lombok.Data;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import java.time.LocalDateTime;


@Data
@Document(collection = "logs")
public class Log {

    @Id
    private String id;
    private String deviceId;           // 사용자별 로그 구분
    private LocalDateTime createdAt;    // 로그 생성 시간
    private String message;
    private String logType;
    private String fileHash;
    private LocalDateTime serverTimestamp; // 서버 수집 시간 (무결성 검증용)

    // 생성자
    public Log(String deviceId, LocalDateTime createdAt, String message,
               String logType, String fileHash, LocalDateTime serverTimestamp) {
        this.deviceId = deviceId;
        this.createdAt = createdAt;
        this.message = message;
        this.logType = logType;
        this.fileHash = fileHash;
        this.serverTimestamp = serverTimestamp;
    }
}
