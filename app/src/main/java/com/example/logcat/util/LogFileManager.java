package com.example.logcat.util;

import android.content.ContentResolver; // 리소스에 대한 컨트롤
import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.provider.MediaStore;
import android.util.Log;
import android.widget.Toast;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;

public class LogFileManager {
    private static final String TAG = "LogFileManager";
    private final String filename;
    private static final String RELATIVE_PATH = "Documents/Logs";

    private Uri logFileUri;
    private final ContentResolver contentResolver;
    private final Context context;

    public LogFileManager(Context context, String filename) {
        this.context = context;
        this.contentResolver = context.getContentResolver();
        this.filename = filename;
    }

    public void initializeLogFile() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            Uri externalUri = MediaStore.Files.getContentUri("external");

            ContentValues values = new ContentValues();
            values.put(MediaStore.MediaColumns.DISPLAY_NAME, filename);
            values.put(MediaStore.MediaColumns.MIME_TYPE, "text/plain");
            values.put(MediaStore.MediaColumns.RELATIVE_PATH, RELATIVE_PATH);

            try {
                logFileUri = contentResolver.insert(externalUri, values);
                if (logFileUri == null) {
                    Log.e(TAG, "Failed to create log file in MediaStore.");
                } else {
                    Log.d(TAG, "Log file created: " + logFileUri);
                }
            } catch (Exception e) {
                Log.e(TAG, "Error creating log file: " + e.getMessage());
            }
        } else {
            File logDir = new File(context.getExternalFilesDir(null), RELATIVE_PATH);
            if (!logDir.exists() && !logDir.mkdirs()) {
                Log.e(TAG, "Log directory creation failed.");
                return;
            }

            File logFile = new File(logDir, filename);
            if (!logFile.exists()) {
                try {
                    if (logFile.createNewFile()) {
                        logFileUri = Uri.fromFile(logFile);
                        Log.d(TAG, "Log file created: " + logFile.getAbsolutePath());
                    } else {
                        Log.e(TAG, "Log file creation failed.");
                    }
                } catch (IOException e) {
                    Log.e(TAG, "Error creating log file: " + e.getMessage());
                }
            } else {
                logFileUri = Uri.fromFile(logFile);
                Log.d(TAG, "Log file already exists: " + logFile.getAbsolutePath());
            }
        }
    }

    public boolean isLogFileExists() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try (OutputStream outputStream = contentResolver.openOutputStream(logFileUri, "r")) {
                return outputStream != null;
            } catch (IOException e) {
                return false;
            }
        } else {
            File logDir = new File(context.getExternalFilesDir(null), RELATIVE_PATH);
            File logFile = new File(logDir, filename);
            return logFile.exists();
        }
    }
    public void appendToLogFile(String content) {
        if (logFileUri == null || !isLogFileExists()) {
            Log.e(TAG, "Log file not initialized. Reinitializing...");
            initializeLogFile();
        }

        if (logFileUri == null) {
            Log.e(TAG, "Log file URI is null. Aborting log write.");
            Toast.makeText(context, "Log file not initialized", Toast.LENGTH_SHORT).show();
            return;
        }

        try (OutputStream outputStream = contentResolver.openOutputStream(logFileUri, "wa")) {
            if (outputStream != null) {
                outputStream.write(content.getBytes());
                Log.d(TAG, "Successfully wrote to log file: " + content);
            } else {
                Log.e(TAG, "Failed to open log file stream.");
            }
        } catch (IOException e) {
            Log.e(TAG, "Error writing to log file: " + e.getMessage());
        }
    }
}