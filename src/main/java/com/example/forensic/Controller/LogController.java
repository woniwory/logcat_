package com.example.forensic.Controller;

import com.example.forensic.Service.LogService;
import com.example.forensic.dto.LogRequest;
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
    public ResponseEntity<String> handleLog(@RequestBody LogRequest logRequest) {
        // Append the log and get the written content
        String appendedContent = logService.appendLog(logRequest);

        // Return the appended content in the response
        return ResponseEntity.ok("Appended to file: " + appendedContent);
    }

    @GetMapping("/{logType}")
    public ResponseEntity<String> getLogContents(@PathVariable String logType) {
        String fileContents = logService.readLog(logType);
        return ResponseEntity.ok(fileContents);
    }

}
