package com.example.urovzinject;
import android.app.Service;
import android.content.Intent;
import android.os.*;
import android.util.Log;

/** Every run gets a private process. Results use Binder and logcat only. */
public final class RunnerService extends Service {
    static { System.loadLibrary("uzhost"); }
    static final int RUN = 1, UPDATE = 2, DONE = 3;
    private static native int runNative(String key, String libdir, String backend, int cycles);
    private static native String[] snapshotNative();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private Messenger client;
    private boolean started, finished, bound;
    private final Messenger messenger = new Messenger(new Handler(Looper.getMainLooper()) {
        @Override public void handleMessage(Message message) {
            if (message.what != RUN || started) return;
            started = true;
            client = message.replyTo;
            Bundle data = message.getData();
            final String key = data.getString("superkey", "");
            final String backend = data.getString("backend", "manual");
            final int cycles = data.getInt("cycles", 3);
            data.remove("superkey");
            handler.post(refresh);
            new Thread(() -> {
                int rc;
                try {
                    rc = runNative(key, getApplicationInfo().nativeLibraryDir, backend, cycles);
                } catch (Throwable error) {
                    Log.e("UROVZ-CRC", "RESULT FAIL native runner", error);
                    rc = -1;
                }
                final int result = rc;
                handler.post(() -> {
                    finished = true;
                    handler.removeCallbacks(refresh);
                    send(DONE, result);
                    if (!bound) android.os.Process.killProcess(android.os.Process.myPid());
                });
            }, "uz-controller").start();
        }
    });
    private final Runnable refresh = new Runnable() {
        @Override public void run() {
            send(UPDATE, 0);
            if (!finished) handler.postDelayed(this, 400);
        }
    };
    private void send(int kind, int rc) {
        if (client == null) return;
        Message message = Message.obtain(null, kind, rc, 0);
        Bundle data = new Bundle();
        String[] snapshot = snapshotNative();
        if (snapshot == null || snapshot.length != 4) return;
        data.putString("report", snapshot[0]);
        data.putString("crc", snapshot[1]);
        data.putString("returns", snapshot[2]);
        data.putString("timing", snapshot[3]);
        message.setData(data);
        try { client.send(message); }
        catch (RemoteException error) { client = null; }
    }
    @Override public IBinder onBind(Intent intent) {
        bound = true;
        return messenger.getBinder();
    }
    @Override public boolean onUnbind(Intent intent) {
        bound = false;
        client = null;
        if (finished || !started) android.os.Process.killProcess(android.os.Process.myPid());
        return false;
    }
}
