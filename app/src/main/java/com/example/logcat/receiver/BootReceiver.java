package com.example.logcat.receiver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import com.example.logcat.service.MonitoringService;

public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent){

        if(Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())){
            Log.d("BootReceiver", "Device boot completed. Starting MainActivity");
            Intent serviceIntent = new Intent(context, MonitoringService.class);
            context.startForegroundService(serviceIntent);
        }
    }
}
