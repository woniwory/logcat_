package com.example.logcat.main;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.example.logcat.service.CallLoggingService;
import com.example.logcat.service.MessageLoggingService;
import com.example.logcat.service.MonitoringService;

public class MainActivity extends AppCompatActivity {

    private static final int REQUEST_CODE_PERMISSIONS = 101; // 권한 요청 코드
    private static final String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // 권한 요청
        checkAndRequestPermissions();
    }

    private void checkAndRequestPermissions() {
        // 요청할 권한 리스트
        String[] permissions = {
                Manifest.permission.READ_PHONE_STATE,
                Manifest.permission.READ_CALL_LOG,
                Manifest.permission.RECEIVE_SMS, // SMS 수신 권한
                Manifest.permission.READ_SMS,    // SMS 읽기 권한
                Manifest.permission.READ_MEDIA_IMAGES
        };

        // 권한이 모두 허용되었는지 확인
        boolean allPermissionsGranted = true;
        for (String permission : permissions) {
            if (ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED) {
                allPermissionsGranted = false;
                break;
            }
        }

        if (!allPermissionsGranted) {
            // 권한 요청
            ActivityCompat.requestPermissions(this, permissions, REQUEST_CODE_PERMISSIONS);
        } else {
            // 모든 권한이 허용된 경우 서비스 시작
            startServices();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);

        if (requestCode == REQUEST_CODE_PERMISSIONS) {
            boolean allGranted = true;

            for (int result : grantResults) {
                if (result != PackageManager.PERMISSION_GRANTED) {
                    allGranted = false;
                    break;
                }
            }

            if (allGranted) {
                Log.d(TAG, "모든 권한이 허용되었습니다.");
                // 권한이 허용되었을 때 서비스 시작
                startServices();
            } else {
                Log.e(TAG, "권한이 거부되었습니다.");
                // 권한 거부 시 알림 표시
                showPermissionDeniedDialog();
            }
        }
    }

    private void startServices() {
        startMonitoringService();
        startCallLoggingService();
        startMessageLoggingService();
    }

    private void startMonitoringService() {
        Intent serviceIntent = new Intent(this, MonitoringService.class);
        startService(serviceIntent);
        Log.d(TAG, "MonitoringService started.");
    }

    private void startCallLoggingService() {
        Intent serviceIntent = new Intent(this, CallLoggingService.class);
        startService(serviceIntent);
    }

    private void startMessageLoggingService() {
        Intent serviceIntent = new Intent(this, MessageLoggingService.class);
        startService(serviceIntent);
        Log.d(TAG, "MessageLoggingService started.");
    }


    private void showPermissionDeniedDialog() {
        new AlertDialog.Builder(this)
                .setTitle("권한 필요")
                .setMessage("앱의 기능을 사용하려면 필요한 권한을 허용해야 합니다. 설정에서 권한을 활성화해주세요.")
                .setPositiveButton("설정으로 이동", (dialog, which) -> {
                    // 앱 설정 화면으로 이동
                    Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                    Uri uri = Uri.fromParts("package", getPackageName(), null);
                    intent.setData(uri);
                    startActivity(intent);
                })
                .setNegativeButton("취소", (dialog, which) -> {
                    Toast.makeText(this, "권한이 없으면 앱을 사용할 수 없습니다.", Toast.LENGTH_SHORT).show();
                })
                .show();
    }
}