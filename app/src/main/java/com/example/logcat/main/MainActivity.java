package com.example.logcat.main;

import android.Manifest; // 권한을 요청하는 클래스
import android.content.Intent; // 액티비티, 앱과 상호작용을 위한 클래스
import android.content.pm.PackageManager; // 설치된 앱의 정보, 권한 상태를 관리하는 클래스
import android.net.Uri; // 콘텐츠나 데이터의 위치를 지정해주는 클래스
import android.os.Bundle; // 키-값 형태로 데이터를 저장하고 전달하는 클래스
import android.provider.Settings; // 시스템 설정을 관리하거나 접근하는 클래스 (intent와 함께쓰임) -> intent에게 전달하면 행동을함
import android.util.Log; // 로그를 기록하는 클래스
import android.widget.Toast; // 간단한 메시지를 잠깐 표시하는 UI 요소

import androidx.annotation.NonNull; // NULL이 되면 안되는 부분을 위한 클래스
import androidx.appcompat.app.AlertDialog; // 대화 상자를 만드는 클래스
import androidx.appcompat.app.AppCompatActivity; // 액티비티 호환을 유지하기 위한 클래스
import androidx.core.app.ActivityCompat; // 권한 요청을 더 쉽게 처리하기 위한 클래스
import androidx.core.content.ContextCompat; // 컨텍스트와 관련된 작업에 대해 호환을 유지하기 위한 클래스

import com.example.logcat.service.CallLoggingService; // 지금부터 CallLoggingService라고 하면 com.example.logcat.service.CallLoggingService라고 생각해라
import com.example.logcat.service.MessageLoggingService;
import com.example.logcat.service.AntiForensicMonitoringService;
import com.example.logcat.service.BluetoothLoggingService;

public class MainActivity extends AppCompatActivity { // 원래 이름은 androidx.appcompat.app.AppCompatActivity임
    private static final int REQUEST_CODE_PERMISSIONS = 101; // 권한 요청 코드
    private static final String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState); // 앱이 비정상 종료되면 복구하기 위해..
        // 권한 요청
        checkAndRequestPermissions();
    }

    // 해당 코드를 한 번에 요청할 수는 없는가?
    private void checkAndRequestPermissions() {
        // 요청할 권한 리스트
        String[] permissions = {
                Manifest.permission.READ_PHONE_STATE, // static class임을 알 수 있음.
                Manifest.permission.READ_CALL_LOG,
                Manifest.permission.RECEIVE_SMS, // SMS 수신 권한
                Manifest.permission.READ_SMS,    // SMS 읽기 권한
                Manifest.permission.READ_MEDIA_IMAGES,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_ADMIN,
                Manifest.permission.ACCESS_FINE_LOCATION,
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
        startBluetoothLoggingService();
    }

    private void startMonitoringService() {
        Intent serviceIntent = new Intent(this, AntiForensicMonitoringService.class);
        startService(serviceIntent);
        Log.d(TAG, "MonitoringService started.");
    }

    private void startCallLoggingService() {
        Intent serviceIntent = new Intent(this, CallLoggingService.class);
        startService(serviceIntent);
        Log.d(TAG, "CallLoggingService started.");
    }

    private void startMessageLoggingService() {
        Intent serviceIntent = new Intent(this, MessageLoggingService.class);
        startService(serviceIntent);
        Log.d(TAG, "MessageLoggingService started.");
    }

    private void startBluetoothLoggingService() {
        Intent intent = new Intent(this, BluetoothLoggingService.class);
        startService(intent);
        Log.d(TAG, "BluetoothLoggingService started");
    }


    private void showPermissionDeniedDialog() {
        new AlertDialog.Builder(this) // 팝업 창을 생성
                .setTitle("권한 필요")
                .setMessage("앱의 기능을 사용하려면 필요한 권한을 허용해야 합니다. 설정에서 권한을 활성화해주세요.")
                .setPositiveButton("설정으로 이동", (dialog, which) -> {
                    // 앱 설정 화면으로 이동
                    Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                    Uri uri = Uri.fromParts("package", getPackageName(), null);
                    intent.setData(uri); // 현재 패키지에 대하여
                    startActivity(intent); // intent해라
                })
                .setNegativeButton("취소", (dialog, which) -> {
                    Toast.makeText(this, "권한이 없으면 앱을 사용할 수 없습니다.", Toast.LENGTH_SHORT).show();
                })
                .show();
    }
}