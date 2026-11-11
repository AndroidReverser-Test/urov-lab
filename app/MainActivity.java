package com.example.urovz;

import android.app.Activity;
import android.os.Bundle;
import android.text.InputType;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

public final class MainActivity extends Activity {
    static { System.loadLibrary("urovz"); }
    private static native String runNative(String key, boolean baseline);
    private boolean running;
    private EditText keyField;
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
        keyField = new EditText(this);
        keyField.setSingleLine(true);
        keyField.setHint("模块密钥 / Module key · 32 hex");
        keyField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        String key = getIntent().getStringExtra("key");
        if (key != null) keyField.setText(key);
        layout.addView(keyField);
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
        String key = keyField.getText().toString().trim();
        output.setText("正在测试 / Running…");
        new Thread(() -> {
            String result;
            try {
                result = runNative(key, baseline);
            } catch (Throwable e) {
                result = "RESULT FAIL " + e;
            }
            try (FileOutputStream file = new FileOutputStream(new File(getFilesDir(), "report.txt"))) {
                file.write(result.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                result += "\nReport file error " + e;
            }
            final String text = result;
            runOnUiThread(() -> {
                running = false;
                output.setText(text);
            });
        }, "urovz-test").start();
    }
}
