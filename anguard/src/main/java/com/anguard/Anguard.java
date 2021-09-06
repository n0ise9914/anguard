package com.anguard;

import android.content.Context;

public class Anguard {

    static {
        System.loadLibrary("anguard");
    }

    public static native void initialize(Context context);

    public static native String getToken(String str);

}
