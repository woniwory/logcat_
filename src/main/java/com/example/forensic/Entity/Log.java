package com.example.forensic.Entity;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document(collection = "logs")
public class Log {

    @Id
    private String id;
    private String deviceId; // 사용자별 로그 구분
    private int sequenceNumber;
    private String timestamp;
    private String message;
    private String logType;

    // 생성자
    public Log(String deviceId, int sequenceNumber, String timestamp, String message, String logType) {
        this.deviceId = deviceId;
        this.sequenceNumber = sequenceNumber;
        this.timestamp = timestamp;
        this.message = message;
        this.logType = logType;
    }

    // Getter & Setter
}
