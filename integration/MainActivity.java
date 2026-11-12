package com.example.urovzinject;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.widget.TextView;
import android.widget.ScrollView;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

public final class MainActivity extends Activity {
    static { System.loadLibrary("uzhost"); }
    private static native int startNative(String key);
    private final Handler handler = new Handler();
    private TextView output;
    private final Runnable refresh = new Runnable() {
        @Override public void run() {
            File file = new File(getFilesDir(), "report.txt");
            try (FileInputStream stream = new FileInputStream(file)) {
                byte[] bytes = new byte[(int)file.length()];
                int n = stream.read(bytes);
                if (n > 0) output.setText("UROV-Z · KCLF / Dobby / CRC\n\n" + new String(bytes, 0, n, StandardCharsets.UTF_8));
            } catch (Exception ignored) { }
            handler.postDelayed(this, 500);
        }
    };
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        output = new TextView(this);
        output.setTextSize(14);
        output.setPadding(24, 24, 24, 24);
        output.setTextIsSelectable(true);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(output);
        setContentView(scroll);
        String key = getIntent().getStringExtra("key");
        output.setText("请使用 integration/device-test.ps1 启动测试。\nWaiting for the integration runner.");
        if (key != null && key.matches("[0-9a-fA-F]{32}")) {
            getFilesDir();
            int rc = startNative(key);
            output.append("\nNative start: " + rc);
            if (rc == 0) handler.post(refresh);
        }
    }
    @Override public void onDestroy() {
        handler.removeCallbacks(refresh);
        super.onDestroy();
    }
}
