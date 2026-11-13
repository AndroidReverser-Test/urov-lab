package com.example.urovz;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public final class MainActivity extends Activity {
    static { System.loadLibrary("urovz"); }
    private static native String runNative(boolean baseline);
    private boolean running;
    private TextView output;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int padding = (int) (20 * getResources().getDisplayMetrics().density);
        layout.setPadding(padding, padding, padding, padding);
        TextView heading = new TextView(this);
        heading.setText("UROV-Z · PAGE_AP / all-callers");
        heading.setTextSize(21);
        layout.addView(heading);
        TextView keyInfo = new TextView(this);
        keyInfo.setText("模块密钥固定为 MD5(urov-lab)\n结果仅显示在界面和 UROVZ logcat");
        layout.addView(keyInfo);
        Button test = new Button(this);
        test.setText("运行完整测试 / Run tests");
        test.setOnClickListener(v -> start(false));
        layout.addView(test);
        Button baseline = new Button(this);
        baseline.setText("运行基线 / Run baseline");
        baseline.setOnClickListener(v -> start(true));
        layout.addView(baseline);
        output = new TextView(this);
        output.setTextIsSelectable(true);
        output.setTextSize(13);
        output.setText("测试结果将显示在此处。\nTest results appear here.");
        ScrollView scroll = new ScrollView(this);
        scroll.addView(output);
        layout.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(layout);
        if (getIntent().getBooleanExtra("autorun", false)) {
            start(getIntent().getBooleanExtra("baseline", false));
        }
    }

    private void start(boolean baseline) {
        if (running) return;
        running = true;
        output.setText("正在测试 / Running…");
        new Thread(() -> {
            String result;
            try {
                result = runNative(baseline);
            } catch (Throwable e) {
                result = "RESULT FAIL " + e;
            }
            final String text = result;
            runOnUiThread(() -> {
                running = false;
                output.setText(text);
            });
        }, "urovz-test").start();
    }
}
