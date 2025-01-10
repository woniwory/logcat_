package com.example.logcat.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.annotation.RequiresPermission;
import androidx.core.app.NotificationCompat;

import com.example.logcat.R;
import com.example.logcat.util.LogFileManager;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class BluetoothLoggingService extends Service {
    private static final String CHANNEL_ID = "MonitoringBluetoothServiceChannel";
    private static final String TAG = "BluetoothLoggingService";

    public LogFileManager logFileManager;
    private BluetoothAdapter bluetoothAdapter;
    private BluetoothProfile a2dpProfile;
    private BluetoothProfile headsetProfile;

    private final BroadcastReceiver bluetoothReceiver = new BroadcastReceiver() {
        @RequiresPermission(value = "android.permission.BLUETOOTH_CONNECT")
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();

            // 권한 확인
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                    context.checkSelfPermission(android.Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                Log.e(TAG, "BLUETOOTH_CONNECT permission not granted in onReceive");
                return;
            }

            try {
                if (BluetoothDevice.ACTION_ACL_CONNECTED.equals(action) || BluetoothDevice.ACTION_ACL_DISCONNECTED.equals(action)) {
                    BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    if (device != null) {
                        String logMessage = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date())
                                + (BluetoothDevice.ACTION_ACL_CONNECTED.equals(action) ?
                                " Bluetooth connected to: " : " Bluetooth disconnected from: ")
                                + device.getName() + " [" + device.getAddress() + "]\n";
                        logToFile(logMessage);

                        // 연결된 후 작업 추적
                        if (BluetoothDevice.ACTION_ACL_CONNECTED.equals(action)) {
                            trackBluetoothActivity(device);
                        }
                    } else {
                        Log.e(TAG, "Device is null on " + action);
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "Failed to process Bluetooth event", e);
            }
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();

        createNotificationChannel();
        startForeground(1, getNotification("Monitoring Bluetooth connections..."));

        bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        logFileManager = new LogFileManager(this, "BluetoothLogs.txt");
        logFileManager.initializeLogFile();

        startBluetoothMonitoring();

        // Register for Bluetooth events
        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothDevice.ACTION_ACL_CONNECTED);
        filter.addAction(BluetoothDevice.ACTION_ACL_DISCONNECTED);
        filter.addAction(BluetoothAdapter.ACTION_STATE_CHANGED); // 추가된 필터
        filter.addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED); // 추가된 필터
        registerReceiver(bluetoothReceiver, filter);

        Log.d(TAG, "Service created");
    }

    private void startBluetoothMonitoring() {
        if (bluetoothAdapter == null) {
            Log.e(TAG, "Bluetooth is not supported on this device");
            stopSelf();
            return;
        }

        // A2DP 프로파일 초기화
        bluetoothAdapter.getProfileProxy(this, new BluetoothProfile.ServiceListener() {
            @Override
            public void onServiceConnected(int profile, BluetoothProfile proxy) {
                if (profile == BluetoothProfile.A2DP) {
                    a2dpProfile = proxy;
                    logConnectedDevices(proxy, "A2DP");
                }
            }

            @Override
            public void onServiceDisconnected(int profile) {
                Log.d(TAG, "A2DP profile disconnected");
            }
        }, BluetoothProfile.A2DP);

        // HEADSET 프로파일 초기화
        bluetoothAdapter.getProfileProxy(this, new BluetoothProfile.ServiceListener() {
            @Override
            public void onServiceConnected(int profile, BluetoothProfile proxy) {
                if (profile == BluetoothProfile.HEADSET) {
                    headsetProfile = proxy;
                    logConnectedDevices(proxy, "HEADSET");
                }
            }

            @Override
            public void onServiceDisconnected(int profile) {
                Log.d(TAG, "HEADSET profile disconnected");
            }
        }, BluetoothProfile.HEADSET);
    }

    private void logConnectedDevices(BluetoothProfile proxy, String profileName) {
        List<BluetoothDevice> connectedDevices = proxy.getConnectedDevices();
        for (BluetoothDevice device : connectedDevices) {
            logBluetoothConnection(device, profileName);
            trackBluetoothActivity(device);
        }
    }

    private void logBluetoothConnection(BluetoothDevice device, String profileName) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                checkSelfPermission(android.Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            Log.e(TAG, "BLUETOOTH_CONNECT permission not granted");
            return;
        }
        try {
            String deviceName = device != null ? device.getName() : "Unknown Device";
            String deviceAddress = device != null ? device.getAddress() : "Unknown Address";

            String logMessage = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date())
                    + " Connected to Bluetooth device (" + profileName + "): " + deviceName
                    + " [" + deviceAddress + "]\n";
            logToFile(logMessage);
        } catch (SecurityException e) {
            Log.e(TAG, "Failed to log Bluetooth connection due to missing permission", e);
        }
    }

    private void trackBluetoothActivity(BluetoothDevice device) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                checkSelfPermission(android.Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            Log.e(TAG, "BLUETOOTH_CONNECT permission not granted");
            return;
        }

        try {
            if (device == null) {
                Log.e(TAG, "Cannot track activity for a null device.");
                return;
            }

            // A2DP 프로파일 확인
            if (a2dpProfile != null && a2dpProfile.getConnectionState(device) == BluetoothProfile.STATE_CONNECTED) {
                String logMessage = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date())
                        + " Audio streaming started on (A2DP): " + device.getName() + "\n";
                logToFile(logMessage);
            }

            // HEADSET 프로파일 확인
            if (headsetProfile != null && headsetProfile.getConnectionState(device) == BluetoothProfile.STATE_CONNECTED) {
                String logMessage = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date())
                        + " Audio streaming started on (HEADSET): " + device.getName() + "\n";
                logToFile(logMessage);
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to track Bluetooth activity", e);
        }
    }

    private void logToFile(String message) {
        if (logFileManager != null) {
            logFileManager.appendToLogFile(message);
        }
        Log.d(TAG, message);
    }

    private void stopBluetoothMonitoring() {
        if (a2dpProfile != null) {
            bluetoothAdapter.closeProfileProxy(BluetoothProfile.A2DP, a2dpProfile);
            a2dpProfile = null;
        }
        if (headsetProfile != null) {
            bluetoothAdapter.closeProfileProxy(BluetoothProfile.HEADSET, headsetProfile);
            headsetProfile = null;
        }
        unregisterReceiver(bluetoothReceiver);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && intent.hasExtra("eventLog")) {
            String eventLog = intent.getStringExtra("eventLog");
            if (eventLog != null && logFileManager != null) {
                logToFile(eventLog);
            }
        }
        return START_STICKY;
    }

    private Notification getNotification(String contentText) {
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("Bluetooth Monitoring Service")
                .setContentText(contentText)
                .setSmallIcon(R.mipmap.ic_launcher)
                .build();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Bluetooth Monitoring Service Channel",
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
        stopBluetoothMonitoring();
        Log.d(TAG, "Service destroyed");
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}