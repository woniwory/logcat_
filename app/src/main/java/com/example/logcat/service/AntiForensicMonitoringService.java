package com.example.logcat.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.ContentObserver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.provider.MediaStore;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import com.example.logcat.util.LogFileManager;
import com.example.logcat.R;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class AntiForensicMonitoringService extends Service {
    private static final String CHANNEL_ID = "MonitoringServiceChannel";
    private BroadcastReceiver timeChangeReceiver;
    private final Handler handler = new Handler();
    private long lastCheckedTime = System.currentTimeMillis();
    private ContentObserver mediaStoreObserver;
    private LogFileManager logFileManager;

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d("MonitoringService", "Service started.");

        createNotificationChannel();
        Notification notification = getNotification();
        startForeground(1, notification);

        logFileManager = new LogFileManager(this, "AntiForensicLog.txt");
        // Initialize log file
        logFileManager.initializeLogFile();

        // Monitoring anti-forensic actions
        monitorAntiForensicActions();
        monitorShutdownAndReboot();
        monitoringLogcatClear();
        monitorMediaStoreChanges();
    }

    private void monitorMediaStoreChanges() {
        ContentResolver resolver = getContentResolver();
        Uri mediaUri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI;

        mediaStoreObserver = new ContentObserver(new Handler()) {
            @Override
            public void onChange(boolean selfChange, Uri uri) {
                super.onChange(selfChange, uri);

                if (uri != null) {
                    String logMessage = getMediaDetails(uri);
                    logFileManager.appendToLogFile(logMessage);
                }
            }
        };
        resolver.registerContentObserver(mediaUri, true, mediaStoreObserver);
        Log.d("MonitoringService", "MediaStore change observer registered");
    }


    private String getMediaDetails(Uri uri) {
        ContentResolver resolver = getContentResolver();
        String logMessage = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date())
                + " MediaStore changed: " + uri + "\n";

        // 명시적으로 필요한 필드 요청
        String[] projection = {
                MediaStore.Images.Media.DISPLAY_NAME,
                MediaStore.Images.Media.RELATIVE_PATH,
                MediaStore.Images.Media.DATE_TAKEN // 사진이 찍힌 날짜와 시간
        };

        try (Cursor cursor = resolver.query(uri, projection, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                // DISPLAY_NAME 필드로 파일 이름 확인
                int displayNameIndex = cursor.getColumnIndex(MediaStore.Images.Media.DISPLAY_NAME);
                if (displayNameIndex >= 0) {
                    String fileName = cursor.getString(displayNameIndex);
                    logMessage += "File Name (DISPLAY_NAME): " + fileName + "\n";
                } else {
                    logMessage += "File Name column not found\n";
                }

                // RELATIVE_PATH 필드로 파일 경로 확인
                int relativePathIndex = cursor.getColumnIndex(MediaStore.Images.Media.RELATIVE_PATH);
                if (relativePathIndex >= 0) {
                    String relativePath = cursor.getString(relativePathIndex);
                    logMessage += "Relative Path: " + relativePath + "\n";
                } else {
                    logMessage += "Relative Path column not found\n";
                }

                // DATE_TAKEN 필드로 사진이 찍힌 날짜와 시간 확인
                int dateTakenIndex = cursor.getColumnIndex(MediaStore.Images.Media.DATE_TAKEN);
                if (dateTakenIndex >= 0) {
                    long dateTaken = cursor.getLong(dateTakenIndex);
                    logMessage += "Modifed After Date: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date(dateTaken)) + "\n";
                } else {
                    logMessage += "Date Taken column not found\n";
                }
            } else {
                logMessage += "Cursor is null or no data found for URI\n";
            }
        } catch (Exception e) {
            e.printStackTrace();
            logMessage += "Error retrieving media details: " + e.getMessage() + "\n";
        }

        return logMessage;
    }
    
    /* Timestamp Change 감지 */
    private void monitorAntiForensicActions() {
        timeChangeReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                String action = intent.getAction();

                if (Intent.ACTION_TIME_CHANGED.equals(action) || Intent.ACTION_DATE_CHANGED.equals(action)) {
                    // Check if auto time setting is enabled
                    boolean isAutoTimeEnabled = android.provider.Settings.Global.getInt(
                            getContentResolver(),
                            android.provider.Settings.Global.AUTO_TIME,
                            0
                    ) == 1;
                    String logMessage = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date())
                            + " Anti-forensic event detected: " + action + "\n";
                    logMessage += new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date()) +
                            " SystemClockTime: Setting time of day to sec=" + System.currentTimeMillis() + "\n";

                    logMessage += new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date()) +
                            " Auto time setting enabled: " + isAutoTimeEnabled + "\n";

                    logMessage += new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date()) +
                            " Before System Time : " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(lastCheckedTime) + "\n";

                    // Log the event
                    logFileManager.appendToLogFile(logMessage);
                }
            }
        };

        IntentFilter filter = new IntentFilter();
        filter.addAction(Intent.ACTION_TIME_CHANGED);
        filter.addAction(Intent.ACTION_DATE_CHANGED);
        registerReceiver(timeChangeReceiver, filter);

        // Schedule periodic time check
        schedulePeriodicTimeCheck();
    }

    /* 전원 꺼짐 및 재부팅 감지 */
    private void monitorShutdownAndReboot() {
        BroadcastReceiver shutdownReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                String action = intent.getAction();
                String logMessage = "";

                if (Intent.ACTION_SHUTDOWN.equals(action)) {
                    logMessage = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date()) +
                            " Device shutdown detected\n";
                }

                logFileManager.appendToLogFile(logMessage);
            }
        };

        IntentFilter filter = new IntentFilter();
        filter.addAction(Intent.ACTION_SHUTDOWN);
        registerReceiver(shutdownReceiver, filter);
    }

    private void schedulePeriodicTimeCheck() {
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                long currentTime = System.currentTimeMillis();
                lastCheckedTime = currentTime;
                handler.postDelayed(this, 1000); // Re-run every second
            }
        }, 1000);
    }

    /* logcat -c 탐지 */
    private void monitoringLogcatClear() {
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                boolean isLogcatCleared = isLogBufferCleared();
                if (isLogcatCleared) {
                   String logMessage =  new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date())
                           + " Logcat buffer cleared (logcat -c detected).\n";
                   logFileManager.appendToLogFile(logMessage);
                }
                handler.postDelayed(this, 5000); // 5초 마다 확인
            }
        }, 5000);
    }

    private boolean isLogBufferCleared() {
        try {
            Process process = Runtime.getRuntime().exec("logcat -d -t 1"); // logcat을 실행할 수 있는 건가?
            int exitValue = process.waitFor();

            if (exitValue == 0) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line = reader.readLine();
                    return line == null || line.isEmpty();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    /* Media File 조작 탐지 */

    private Notification getNotification() {
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("Monitoring Service")
                .setContentText("Monitoring anti-forensic actions...")
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

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (timeChangeReceiver != null) {
            unregisterReceiver(timeChangeReceiver);
        }
        handler.removeCallbacksAndMessages(null); // Stop periodic checks
        Log.d("MonitoringService", "Service stopped.");
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
