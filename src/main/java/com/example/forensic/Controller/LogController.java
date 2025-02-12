package com.example.forensic.Controller;

import com.example.forensic.dto.LogRequest;
import com.example.forensic.Service.LogService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/logs")
public class LogController {

    private final LogService logService;

    public LogController(LogService logService) {
        this.logService = logService;
    }

    @PostMapping
    public String handleLog(@RequestBody LogRequest logRequest) {
        String appendedContent = logService.appendLog(logRequest);

        return appendedContent;
    }


    @GetMapping("/{deviceId}/{logType}")
    public ResponseEntity<String> getLogContents(@PathVariable String deviceId, @PathVariable String logType) {
        String fileContents = logService.readLog(deviceId, logType);
        return ResponseEntity.ok(fileContents);
    }
}
