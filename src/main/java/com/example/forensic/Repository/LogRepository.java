package com.example.forensic.Repository;

import com.example.forensic.Entity.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.stereotype.Repository;
import org.springframework.data.mongodb.core.query.Query;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public class LogRepository {

    @Autowired
    private MongoTemplate mongoTemplate;

    // 동적으로 컬렉션 이름을 받아서 로그 저장
    public void save(Log log) {
        mongoTemplate.save(log);
    }

    // 동적으로 컬렉션 이름을 받아서 deviceId와 logType을 기준으로 로그 조회
    public List<Log> findByDeviceIdAndLogType(String deviceId, String logType) {
        Query query = new Query();
        query.addCriteria(Criteria.where("logType").is(logType));

        return mongoTemplate.find(query, Log.class);
    }

    public List<Log> readLogsWithinDuration(String deviceId, LocalDateTime start, LocalDateTime end) {
        // 날짜 범위 조건
        Criteria criteria = new Criteria();
        criteria.and("deviceId").is(deviceId);
        criteria.and("createdAt").gte(start).lte(end); // createdAt이 start와 end 사이에 있는지 조건 추가

        // Query 객체 생성
        Query query = new Query(criteria);

        // MongoDB에서 쿼리 실행
        return mongoTemplate.find(query, Log.class);
    }
}
