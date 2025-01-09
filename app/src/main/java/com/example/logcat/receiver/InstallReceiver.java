package com.example.logcat.receiver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import com.example.logcat.service.MonitoringService;

public class InstallReceiver extends BroadcastReceiver{
    @Override
    public void onReceive(Context context, Intent intent){
        String action = intent.getAction();
        if(Intent.ACTION_PACKAGE_ADDED.equals(action) || Intent.ACTION_PACKAGE_REPLACED.equals(action)){
            Log.d("InstallReceiver", "App installed or updated. Starting MonitoringService.");

            Intent serviceIntent = new Intent(context, MonitoringService.class);
            context.startForegroundService(serviceIntent);
        }
    }
}