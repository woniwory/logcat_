package com.example.forensic.Entity;

import lombok.*;
import org.springframework.data.annotation.Id;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter

public class Message { // 메시지를 보낸 주체

    private String content;              // 실제 메시지 내용
    private LocalDateTime deviceTimestamp;     // 메시지 생성 시간
    private LocalDateTime serverTimestamp;

}
