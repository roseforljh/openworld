package com.openworld.app.aidl;

oneway interface ISingBoxServiceCallback {
    void onStateChanged(int state, String activeLabel, String lastError, boolean manuallyStopped);
}
