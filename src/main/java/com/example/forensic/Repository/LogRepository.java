package com.example.forensic.Repository;

import com.example.forensic.Entity.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.stereotype.Repository;
import org.springframework.data.mongodb.core.query.Query;

import java.util.List;

@Repository
public class LogRepository {

    @Autowired
    private MongoTemplate mongoTemplate;

    // 동적으로 컬렉션 이름을 받아서 로그 저장
    public void save(Log log, String collectionName) {
        mongoTemplate.save(log, collectionName);
    }

    // 동적으로 컬렉션 이름을 받아서 deviceId와 logType을 기준으로 로그 조회
    public List<Log> findByDeviceIdAndLogType(String deviceId, String logType, String collectionName) {
        Query query = new Query();
        query.addCriteria(Criteria.where("deviceId").is(deviceId).and("logType").is(logType));

        return mongoTemplate.find(query, Log.class, collectionName);
    }
}
