package com.example.urovdetect;

import android.app.Activity;
import android.graphics.Insets;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Log;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {
    private static final String DOBBY_CRC = "dobby-crc";
    static { System.loadLibrary("urovdetect"); }
    private static native String runNative(String mode, int repeats, String key);
    private final Handler handler = new Handler(Looper.getMainLooper());
    private long ticks, lastTick, maxGap;
    private boolean destroyed, running;
    private String keyHex = "";
    private TextView status, heartbeat;
    private Button button;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        String mode = getIntent().getStringExtra("mode");
        String key = getIntent().getStringExtra("key");
        if (key != null) keyHex = key;
        boolean automatic = mode != null && !DOBBY_CRC.equals(mode);

        getWindow().setDecorFitsSystemWindows(false);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setOnApplyWindowInsetsListener((view, insets) -> {
            Insets bars = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            view.setPadding(32 + bars.left, 48 + bars.top, 32 + bars.right, 24 + bars.bottom);
            return insets;
        });
        status = new TextView(this);
        status.setText("Press to check the hooked code against its original file.");
        button = new Button(this);
        button.setText("Check code CRC32");
        layout.addView(button);
        layout.addView(status);
        if (automatic) {
            heartbeat = new TextView(this);
            layout.addView(heartbeat);
        }
        setContentView(layout);
        button.setOnClickListener(v -> start(DOBBY_CRC, 1));
        if (!automatic) return;

        lastTick = SystemClock.elapsedRealtime();
        handler.post(new Runnable() {
            @Override public void run() {
                if (destroyed) return;
                long now = SystemClock.elapsedRealtime();
                maxGap = Math.max(maxGap, now - lastTick);
                lastTick = now;
                ++ticks;
                if (ticks % 10 == 0) heartbeat.setText("UI heartbeat: " + ticks + "   max gap: " + maxGap + " ms");
                handler.postDelayed(this, 10);
            }
        });
        int repeats = Math.max(3, Math.min(200, getIntent().getIntExtra("repeats", 30)));
        start(mode, repeats);
    }

    private void start(String mode, int repeats) {
        if (running) return;
        running = true;
        button.setEnabled(false);
        boolean crc = DOBBY_CRC.equals(mode);
        if (crc) status.setText("Checking code CRC32…");
        long initialTicks = ticks;
        maxGap = 0;
        new Thread(() -> {
            // Test-harness warmup: let ART and the first UI frame settle.
            if (!crc) SystemClock.sleep(1000);
            long begin = SystemClock.elapsedRealtime();
            String result = runNative(mode, repeats, keyHex);
            // Keep an observation window even when the checks finish very quickly.
            if (!crc) {
                long remaining = 350 - (SystemClock.elapsedRealtime() - begin);
                if (remaining > 0) SystemClock.sleep(remaining);
            }
            long elapsed = SystemClock.elapsedRealtime() - begin;
            handler.post(() -> {
                long delivered = ticks - initialTicks;
                boolean ok = result.startsWith("PASS") && (crc || delivered >= 5);
                String report = result + "\nmode=" + mode + " worker_ms=" + elapsed +
                    " ui_ticks=" + delivered + " ui_max_gap_ms=" + maxGap;
                status.setText(crc ? result : report);
                running = false;
                button.setEnabled(true);
                Log.i("urovdetect", "DETECT_RESULT " + (ok ? "PASS" : "FAIL") +
                    " mode=" + mode + " worker_ms=" + elapsed + " ui_ticks=" + delivered +
                    " ui_max_gap_ms=" + maxGap + " native=" + result);
            });
        }, "urov-detector").start();
    }

    @Override public void onDestroy() {
        destroyed = true;
        handler.removeCallbacksAndMessages(null);
        super.onDestroy();
    }
}
