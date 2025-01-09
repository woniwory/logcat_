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
import android.telephony.SmsMessage;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import com.example.logcat.util.LogFileManager;
import com.example.logcat.R;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class MessageLoggingService extends Service {
    private static final String CHANNEL_ID = "MonitoringAppServiceChannel";
    private static final String TAG = "MessageLoggingService";
    private BroadcastReceiver smsReceiver;
    private ContentObserver smsSentObserver;
    private boolean isSmsReceiverInitialized = false;
    private String lastProcessedMessage = null;
    private Uri lastProcessedUri = null;
    private long lastProcessedTimestamp = 0;
    private LogFileManager logFileManager;

    @Override
    public void onCreate() {
        super.onCreate();

        createNotificationChannel();
        Notification notification = getNotification();
        startForeground(1, notification);

        // 로그 파일 이름 고유화
        logFileManager = new LogFileManager(this, "MessageLog.txt");
        logFileManager.initializeLogFile();

        Log.d(TAG, "Service Created");

        initializeSMSReceiver();
        initializeSMSSentObserver();
    }

    private void initializeSMSReceiver() {
        if (isSmsReceiverInitialized) {
            Log.w(TAG, "SMS Receiver is already initialized.");
            return;
        }

        smsReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if ("android.provider.Telephony.SMS_RECEIVED".equals(intent.getAction())) {
                    Object[] pdus = (Object[]) intent.getExtras().get("pdus");
                    if (pdus != null) {
                        for (Object pdu : pdus) {
                            SmsMessage sms = SmsMessage.createFromPdu((byte[]) pdu);
                            String sender = sms.getOriginatingAddress();
                            String message = sms.getMessageBody();

                            if (isDuplicateMessage(message, System.currentTimeMillis())) {
                                Log.w(TAG, "Duplicate SMS detected. Skipping...");
                                continue;
                            }

                            logSMSDetails(sender, message, "Received");
                        }
                    }
                }
            }
        };

        IntentFilter filter = new IntentFilter("android.provider.Telephony.SMS_RECEIVED");
        registerReceiver(smsReceiver, filter);
        isSmsReceiverInitialized = true;
        Log.d(TAG, "SMS Receiver initialized.");
    }

    private void initializeSMSSentObserver() {
        ContentResolver resolver = getContentResolver();
        smsSentObserver = new ContentObserver(new Handler()) {
            @Override
            public void onChange(boolean selfChange, Uri uri) {
                super.onChange(selfChange, uri);

                try (Cursor cursor = resolver.query(
                        Uri.parse("content://sms"),
                        null, null, null, "date DESC")) {

                    if (cursor != null && cursor.moveToFirst()) {
                        int type = cursor.getInt(cursor.getColumnIndexOrThrow("type"));
                        String address = cursor.getString(cursor.getColumnIndexOrThrow("address"));
                        String body = cursor.getString(cursor.getColumnIndexOrThrow("body"));

                        if (type == 2) {
                            if (isDuplicateSentMessage(uri, body)) {
                                Log.w(TAG, "Duplicate Sent SMS detected. Skipping...");
                                return;
                            }

                            logSMSDetails(address, body, "Sent");
                            lastProcessedUri = uri;
                        }
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Failed to retrieve sent SMS: " + e.getMessage());
                }
            }
        };

        resolver.registerContentObserver(Uri.parse("content://sms"), true, smsSentObserver);
        Log.d(TAG, "SMS Sent Observer Registered");
    }

    private boolean isDuplicateMessage(String message, long timestamp) {
        if (message.equals(lastProcessedMessage) && (timestamp - lastProcessedTimestamp < 2000)) {
            return true;
        }
        lastProcessedMessage = message;
        lastProcessedTimestamp = timestamp;
        return false;
    }

    private boolean isDuplicateSentMessage(Uri uri, String body) {
        if (lastProcessedUri != null && lastProcessedUri.equals(uri) && body.equals(lastProcessedMessage)) {
            return true;
        }
        lastProcessedUri = uri;
        lastProcessedMessage = body;
        return false;
    }

    private void logSMSDetails(String sender, String message, String type) {
        String logMessage = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date())
                + " SMS " + type + " to/from: " + sender
                + " Message: " + message + "\n";
        Log.d(TAG, logMessage);
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
                    CHANNEL_ID, "Monitoring Service Channel", NotificationManager.IMPORTANCE_LOW
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
        if (smsReceiver != null) {
            unregisterReceiver(smsReceiver);
        }
        if (smsSentObserver != null) {
            getContentResolver().unregisterContentObserver(smsSentObserver);
        }
        Log.d(TAG, "Service Terminated");
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
