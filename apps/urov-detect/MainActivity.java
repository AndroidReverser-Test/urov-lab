package com.example.urovdetect;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {
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
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 48, 32, 24);
        status = new TextView(this);
        status.setText("Checks run in a worker thread. Results do not block app use.");
        heartbeat = new TextView(this);
        button = new Button(this);
        button.setText("Run passive checks again");
        layout.addView(status); layout.addView(heartbeat); layout.addView(button);
        setContentView(layout);
        button.setOnClickListener(v -> start("passive", 20));
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
        String mode = getIntent().getStringExtra("mode");
        String key = getIntent().getStringExtra("key");
        if (key != null) keyHex = key;
        int repeats = Math.max(3, Math.min(200, getIntent().getIntExtra("repeats", 30)));
        start(mode == null ? "passive" : mode, repeats);
    }

    private void start(String mode, int repeats) {
        if (running) return;
        running = true;
        button.setEnabled(false);
        long initialTicks = ticks;
        maxGap = 0;
        new Thread(() -> {
            // Test-harness warmup: let ART and the first UI frame settle.
            SystemClock.sleep(1000);
            long begin = SystemClock.elapsedRealtime();
            String result = runNative(mode, repeats, keyHex);
            // Keep an observation window even when the checks finish very quickly.
            long remaining = 350 - (SystemClock.elapsedRealtime() - begin);
            if (remaining > 0) SystemClock.sleep(remaining);
            long elapsed = SystemClock.elapsedRealtime() - begin;
            handler.post(() -> {
                long delivered = ticks - initialTicks;
                boolean ok = result.startsWith("PASS") && delivered >= 5;
                String report = result + "\nmode=" + mode + " worker_ms=" + elapsed +
                    " ui_ticks=" + delivered + " ui_max_gap_ms=" + maxGap;
                status.setText(report);
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
