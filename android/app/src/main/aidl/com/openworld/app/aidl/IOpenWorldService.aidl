package com.openworld.app.aidl;

import com.openworld.app.aidl.IOpenWorldServiceCallback;

interface IOpenWorldService {
    int getState();

    String getActiveLabel();

    String getLastError();

    boolean isManuallyStopped();

    void registerCallback(IOpenWorldServiceCallback callback);

    void unregisterCallback(IOpenWorldServiceCallback callback);

    oneway void notifyAppLifecycle(boolean isForeground);

    int hotReloadConfig(String configContent);
}
