package com.example.logcat.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.Build;
import android.os.IBinder;
import android.telephony.PhoneStateListener;
import android.telephony.TelephonyManager;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import com.example.logcat.util.LogFileManager;
import com.example.logcat.R;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class CallLoggingService extends Service {
    private static final String CHANNEL_ID = "MonitoringAppServiceChannel";
    private static final String TAG = "CallLoggingService";
    private TelephonyManager telephonyManager;
    @SuppressWarnings("deprecation")
    private PhoneStateListener phoneStateListener;
    private BroadcastReceiver outgoingCallReceiver;

    private String lastDialedNumber;
    private String incomingCallNumber;
    private long callStartTime;
    private LogFileManager logFileManager;

    @Override
    public void onCreate() {
        super.onCreate();

        createNotificationChannel();
        Notification notification = getNotification();
        startForeground(1, notification);

        logFileManager = new LogFileManager(this, "CallLogs.txt");
        logFileManager.initializeLogFile();
        Log.d(TAG, "서비스 생성됨");

        initializePhoneStateListener();
        initializeOutgoingCallReceiver();
    }

    @SuppressWarnings("deprecation")
    private void initializePhoneStateListener() {
        telephonyManager = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
        phoneStateListener = new PhoneStateListener() {
            @Override
            public void onCallStateChanged(int state, String phoneNumber) {
                Log.d(TAG, "onCallStateChanged: state=" + state + ", phoneNumber=" + phoneNumber);
                lastDialedNumber = phoneNumber;
                switch (state) {
                    case TelephonyManager.CALL_STATE_IDLE: // 통화 종료 또는 전화 받지 않음
                        Log.d(TAG, "CALL_STATE_IDLE: 통화 종료 또는 전화 받지 않음");
                        if (callStartTime > 0) {
                            long callEndTime = System.currentTimeMillis();
                            if (lastDialedNumber != null) { // 발신 통화 종료
                                logCallDetails(lastDialedNumber, callStartTime, callEndTime, "통화 종료");
                            } else if (incomingCallNumber != null) { // 수신 통화 종료
                                logCallDetails(incomingCallNumber, callStartTime, callEndTime, "통화 종료");
                            }
                            callStartTime = 0;
                            lastDialedNumber = null;
                            incomingCallNumber = null;
                        } else if (incomingCallNumber != null) {
                            // 수신 전화 거절 또는 받지 않음
                            logCallDetails(incomingCallNumber, 0, 0, "수신 전화 거절 또는 받지 않음");
                            incomingCallNumber = null;
                        }
                        break;

                    case TelephonyManager.CALL_STATE_OFFHOOK: // 통화 연결
                        Log.d(TAG, "CALL_STATE_OFFHOOK: 통화 연결");
                        callStartTime = System.currentTimeMillis();
                        if (incomingCallNumber != null) {
                            logCallDetails(incomingCallNumber, callStartTime, 0, "수신 통화 시작");
                        } else if (lastDialedNumber != null) {
                            logCallDetails(lastDialedNumber, callStartTime, 0, "발신 통화 시작");
                        }
                        break;

                    case TelephonyManager.CALL_STATE_RINGING: // 수신 전화
                        Log.d(TAG, "CALL_STATE_RINGING, HIHI: 전화 울림");
                        if (phoneNumber != null) {
                            incomingCallNumber = phoneNumber;
                            logCallDetails(incomingCallNumber, 0, 0, "수신 전화 울림");
                        }
                        break;
                }
            }
        };

        telephonyManager.listen(phoneStateListener, PhoneStateListener.LISTEN_CALL_STATE);
    }

    @SuppressWarnings("deprecation")
    private void initializeOutgoingCallReceiver() {
        outgoingCallReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (Intent.ACTION_NEW_OUTGOING_CALL.equals(intent.getAction())) {
                    lastDialedNumber = intent.getStringExtra(Intent.EXTRA_PHONE_NUMBER);
                    Log.d(TAG, "발신 전화: " + lastDialedNumber);
                    logCallDetails(lastDialedNumber, 0, 0, "발신 전화 시작");
                }
            }
        };

        IntentFilter filter = new IntentFilter(Intent.ACTION_NEW_OUTGOING_CALL);
        registerReceiver(outgoingCallReceiver, filter);
    }

    private void logCallDetails(String number, long startTime, long endTime, String callType) {
        Log.d(TAG, "HIHI");
        String startTimeFormatted = startTime > 0
                ? new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date(startTime))
                : "N/A";
        String endTimeFormatted = endTime > 0
                ? new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date(endTime))
                : "N/A";
        long durationSeconds = (endTime > 0 && startTime > 0) ? (endTime - startTime) / 1000 : 0;

        String logMessage = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date())
                + " Call Type: " + callType
                + " Number: " + number
                + " Start Time: " + startTimeFormatted
                + " End Time: " + endTimeFormatted
                + " Duration: " + durationSeconds + " seconds\n";

        Log.d(TAG, "통화 기록:\n" + logMessage);
        logFileManager.appendToLogFile(logMessage);
    }


    private Notification getNotification() {
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("Monitoring Service")
                .setContentText("Monitoring App Activity actions...")
                .setSmallIcon(R.mipmap.ic_launcher)
                .build();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Monitoring Service Channel",
                    NotificationManager.IMPORTANCE_LOW
            );
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    public void onDestroy() {
        super.onDestroy();
        if (telephonyManager != null && phoneStateListener != null) {
            telephonyManager.listen(phoneStateListener, PhoneStateListener.LISTEN_NONE);
        }
        if (outgoingCallReceiver != null) {
            unregisterReceiver(outgoingCallReceiver);
        }
        Log.d(TAG, "서비스 종료됨");
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}