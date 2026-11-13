package com.example.urovzinject;
import android.app.Activity;
import android.content.*;
import android.os.*;
import android.text.InputType;
import android.view.View;
import android.view.WindowManager;
import android.widget.*;
import java.util.Locale;

public final class MainActivity extends Activity {
    private TextView output, status, timings, crcResult, returnValues, pageResults;
    private EditText superKey, cycles;
    private Spinner backend;
    private Button run;
    private boolean bound, running;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Messenger receiver = new Messenger(new Handler(Looper.getMainLooper()) {
        @Override public void handleMessage(Message message) {
            if (message.what != RunnerService.UPDATE && message.what != RunnerService.DONE) return;
            String report = message.getData().getString("report", "");
            output.setText(report.isEmpty() ? "正在初始化测试进程…" : report);
            showCrc(message.getData().getString("crc", ""));
            showReturns(message.getData().getString("returns", ""));
            showTiming(message.getData().getString("timing", ""));
            if (message.what == RunnerService.DONE) {
                running = false;
                status.setText(message.arg1 == 0 ? "测试通过 · 已注销覆盖并撤销 10 个 hook" : "测试失败 · 请查看下方日志");
                release();
                handler.postDelayed(() -> controls(true), 750);
            }
        }
    });
    private final ServiceConnection connection = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName name, IBinder binder) {
            Message message = Message.obtain(null, RunnerService.RUN);
            Bundle data = new Bundle();
            data.putString("superkey", superKey.getText().toString());
            data.putString("backend", backend.getSelectedItem().toString());
            data.putInt("cycles", Integer.parseInt(cycles.getText().toString()));
            message.setData(data);
            message.replyTo = receiver;
            try { new Messenger(binder).send(message); }
            catch (RemoteException error) { failed("无法启动测试服务：" + error); }
        }
        @Override public void onServiceDisconnected(ComponentName name) {
            if (running) failed("测试进程意外退出；本轮判为失败。请查看 UROVZ-CRC 和 crash 日志。");
        }
        @Override public void onBindingDied(ComponentName name) {
            if (running) failed("测试服务连接失效；本轮判为失败。");
        }
    };
    private void release() {
        if (bound) { bound = false; unbindService(connection); }
    }
    private void failed(String message) {
        running = false;
        status.setText(message);
        android.util.Log.e("UROVZ-CRC", "RESULT FAIL " + message);
        controls(true);
        release();
    }
    private void controls(boolean enabled) {
        run.setEnabled(enabled);
        cycles.setEnabled(enabled);
        backend.setEnabled(enabled);
        superKey.setEnabled(enabled);
    }
    private static String field(String line, String name) {
        String prefix = name + "=";
        for (String token : line.split(" "))
            if (token.startsWith(prefix)) return token.substring(prefix.length());
        return "—";
    }
    private static String stage(String name) {
        switch (name) {
            case "baseline": return "原始函数";
            case "module_absent": return "模块未加载";
            case "loaded_inactive": return "已加载，未 hook";
            case "hooked_uncovered": return "已 hook，未覆盖";
            case "overlay": return "10 页覆盖生效";
            case "deactivated": return "已注销覆盖，hook 保留";
            case "unhooked": return "已撤销 hook";
            default: return name;
        }
    }
    private static String integrity(String value) {
        switch (value) {
            case "MATCH": return "与基线一致";
            case "CHANGED": return "检出代码修改";
            case "DIVERGED": return "三通道不一致";
            default: return "读取失败";
        }
    }
    private void showCrc(String snapshot) {
        if (snapshot.isEmpty()) return;
        StringBuilder summary = new StringBuilder(), pages = new StringBuilder("页   基线      direct    readv     proc      判定\n");
        for (String line : snapshot.split("\n")) {
            if (line.startsWith("CRC ")) {
                summary.append("CRC 校验 · ").append(stage(field(line, "stage")))
                    .append("\n基线    ").append(field(line, "baseline"))
                    .append("\ndirect  ").append(field(line, "direct"))
                    .append("\nreadv   ").append(field(line, "readv"))
                    .append("\nproc    ").append(field(line, "proc"))
                    .append("\n").append(integrity(field(line, "integrity")))
                    .append(" · 预期：").append(integrity(field(line, "expected")))
                    .append("\n阶段判定 ").append(field(line, "result"))
                    .append(" · 页校验 ").append(field(line, "pages"));
            } else if (line.startsWith("PAGE ")) {
                pages.append(String.format(Locale.ROOT, "%2s   %s  %s  %s  %s  %s\n",
                    field(line, "index"), field(line, "baseline"), field(line, "direct"),
                    field(line, "readv"), field(line, "proc"), field(line, "result")));
            } else if (line.startsWith("OVERLAY_CRC ")) {
                summary.append("\n覆盖期记录：").append(field(line, "result"))
                    .append(" · ").append(integrity(field(line, "integrity")))
                    .append("\n").append(field(line, "direct")).append(" / ")
                    .append(field(line, "readv")).append(" / ").append(field(line, "proc"));
            }
        }
        crcResult.setText(summary);
        pageResults.setText(pages);
    }
    private void showReturns(String snapshot) {
        if (snapshot.isEmpty()) return;
        StringBuilder rows = new StringBuilder();
        for (String line : snapshot.split("\n")) {
            if (line.startsWith("RETURNS ")) {
                rows.append("10 个函数返回值 · 采样 #").append(field(line, "tick"))
                    .append("\n").append(stage(field(line, "stage")))
                    .append(" · t=").append(field(line, "elapsed_ms")).append(" ms")
                    .append("\n函数  实际  期望  原值  覆盖期实测  判定\n");
            } else if (line.startsWith("RETURN ")) {
                String active = field(line, "overlay_actual");
                rows.append(String.format(Locale.ROOT, "f%-2s %5s %5s %4s %7s   %s\n",
                    field(line, "index"), field(line, "actual"), field(line, "expected"),
                    field(line, "baseline"), "-1".equals(active) ? "—" : active, field(line, "result")));
            }
        }
        returnValues.setText(rows);
    }
    private void showTiming(String snapshot) {
        if (snapshot.isEmpty()) return;
        String label = "module_absent_to_overlay".equals(field(snapshot, "compare"))
            ? "未加载 → 覆盖" : "未覆盖 → 覆盖";
        StringBuilder text = new StringBuilder("CRC 耗时中位数 µs · " + label);
        for (String channel : new String[]{"direct", "readv", "proc"})
            text.append("\n").append(channel).append(": ")
                .append(field(snapshot, channel + "_us").replace("/", " → "));
        timings.setText(text);
    }
    private TextView readout(int size) {
        TextView view = new TextView(this);
        view.setTextSize(size);
        view.setTextIsSelectable(true);
        view.setTypeface(android.graphics.Typeface.MONOSPACE);
        view.setPadding(0, 12, 0, 12);
        return view;
    }
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = (int)(16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);
        layout.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(pad + insets.getSystemWindowInsetLeft(), pad + insets.getSystemWindowInsetTop(),
                pad + insets.getSystemWindowInsetRight(), pad + insets.getSystemWindowInsetBottom());
            return insets.consumeSystemWindowInsets();
        });
        TextView title = new TextView(this);
        title.setText("UROV · 10 页 CRC 压力测试");
        title.setTextSize(22);
        layout.addView(title);
        TextView description = new TextView(this);
        description.setText("10 页 CRC · 返回值每秒实测，切换/计时期间延后\n"
            + "模块密钥固定 MD5(urov-lab) · 日志 UROVZ-CRC\n"
            + "首次自动加载 /data/local/tmp/urov-z.kpm");
        layout.addView(description);
        superKey = new EditText(this);
        superKey.setSingleLine(true);
        superKey.setHint("设备 kpatch SuperKey（仅保留在内存）");
        superKey.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        superKey.setSaveEnabled(false);
        String key = getIntent().getStringExtra("superkey");
        if (key != null) superKey.setText(key);
        getIntent().removeExtra("superkey");
        layout.addView(superKey);
        LinearLayout options = new LinearLayout(this);
        backend = new Spinner(this);
        backend.setAdapter(new ArrayAdapter<String>(this, android.R.layout.simple_spinner_dropdown_item,
            new String[]{"manual", "linker"}));
        backend.setSelection("linker".equals(getIntent().getStringExtra("backend")) ? 1 : 0);
        options.addView(backend, new LinearLayout.LayoutParams(0, -2, 1));
        cycles = new EditText(this);
        cycles.setInputType(InputType.TYPE_CLASS_NUMBER);
        cycles.setSingleLine(true);
        cycles.setHint("轮数 1–20");
        cycles.setText(Integer.toString(getIntent().getIntExtra("cycles", 3)));
        options.addView(cycles, new LinearLayout.LayoutParams(0, -2, 1));
        layout.addView(options);
        run = new Button(this);
        run.setText("运行 / 复测");
        run.setOnClickListener(v -> start());
        layout.addView(run);
        status = new TextView(this);
        status.setText("就绪 · 结果只显示在界面和 logcat");
        layout.addView(status);
        LinearLayout results = new LinearLayout(this);
        results.setOrientation(LinearLayout.VERTICAL);
        crcResult = readout(13);
        crcResult.setText("等待 CRC 校验结果…");
        results.addView(crcResult);
        returnValues = readout(12);
        returnValues.setText("等待 10 个函数的返回值…");
        HorizontalScrollView returnsScroll = new HorizontalScrollView(this);
        returnsScroll.addView(returnValues);
        results.addView(returnsScroll);
        timings = readout(12);
        results.addView(timings);
        pageResults = readout(12);
        HorizontalScrollView pageScroll = new HorizontalScrollView(this);
        pageScroll.addView(pageResults);
        pageScroll.setVisibility(View.GONE);
        Button details = new Button(this);
        details.setText("展开 10 页 CRC 明细");
        details.setOnClickListener(v -> {
            boolean open = pageScroll.getVisibility() != View.VISIBLE;
            pageScroll.setVisibility(open ? View.VISIBLE : View.GONE);
            details.setText(open ? "收起 10 页 CRC 明细" : "展开 10 页 CRC 明细");
        });
        results.addView(details);
        results.addView(pageScroll);
        output = readout(11);
        output.setVisibility(View.GONE);
        Button logs = new Button(this);
        logs.setText("展开最近日志");
        logs.setOnClickListener(v -> {
            boolean open = output.getVisibility() != View.VISIBLE;
            output.setVisibility(open ? View.VISIBLE : View.GONE);
            logs.setText(open ? "收起最近日志" : "展开最近日志");
        });
        results.addView(logs);
        results.addView(output);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(results);
        layout.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(layout);
        layout.requestApplyInsets();
        if (getIntent().getBooleanExtra("autorun", false)) handler.post(this::start);
    }
    private void start() {
        if (running) return;
        int count;
        try { count = Integer.parseInt(cycles.getText().toString()); }
        catch (NumberFormatException error) { status.setText("轮数必须为 1–20"); return; }
        if (count < 1 || count > 20) { status.setText("轮数必须为 1–20"); return; }
        if (superKey.getText().length() == 0 || superKey.getText().length() >= 64) {
            status.setText("请输入有效的设备 kpatch SuperKey"); return;
        }
        running = true;
        controls(false);
        status.setText("正在测试 · 首次加载前采集无模块基线；复测比较覆盖关闭/启用");
        output.setText("");
        crcResult.setText("等待 CRC 校验结果…");
        returnValues.setText("等待 10 个函数的返回值…");
        pageResults.setText("");
        timings.setText("等待 CRC 耗时样本…");
        bound = bindService(new Intent(this, RunnerService.class), connection, BIND_AUTO_CREATE);
        if (!bound) failed("无法绑定独立测试进程");
    }
    @Override public void onDestroy() {
        handler.removeCallbacksAndMessages(null);
        release();
        super.onDestroy();
    }
}
