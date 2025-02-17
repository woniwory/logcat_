package com.example.forensic.Controller;

import com.example.forensic.dto.LogRequest;
import com.example.forensic.Service.LogService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

@RestController
@RequestMapping("/logs")
public class LogController {

    private final LogService logService;

    public LogController(LogService logService) {
        this.logService = logService;
    }

    // 로그 작성 및 해시 저장
    @PostMapping
    public ResponseEntity<String> handleLog(@RequestBody LogRequest logRequest) throws IOException, NoSuchAlgorithmException {
        String result = logService.appendLogAndSaveHash(logRequest);
        return ResponseEntity.ok(result);
    }

    // 로그 파일 조회
    @GetMapping("/{deviceId}/{logType}")
    public ResponseEntity<String> getLogContents(@PathVariable String deviceId, @PathVariable String logType) {
        String fileContents = logService.readLog(deviceId, logType);
        return ResponseEntity.ok(fileContents);
    }
}
