#!/usr/bin/env bash
set -euo pipefail

serial=${1:?emulator serial required}
probe_dir=$(mktemp -d "$RUNNER_TEMP/native-bridge-probe.XXXXXX")
trap 'rm -rf "$probe_dir"' EXIT
mkdir -p "$probe_dir/classes" "$probe_dir/lib/arm64-v8a"

ndk=$(find "$ANDROID_HOME/ndk" -mindepth 1 -maxdepth 1 -type d -print | sort -V | tail -n 1)
test -n "$ndk"
build_tools=$(find "$ANDROID_HOME/build-tools" -mindepth 1 -maxdepth 1 -type d -print | sort -V | tail -n 1)
test -n "$build_tools"
android_jar="$ANDROID_HOME/platforms/android-35/android.jar"
test -f "$android_jar"

cat > "$probe_dir/probe.c" <<'EOF'
#include <jni.h>

JNIEXPORT jint JNICALL Java_org_example_nativeprobe_Probe_value(JNIEnv *env, jobject self) {
    (void)env;
    (void)self;
    return 42;
}
EOF
"$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android23-clang" \
  -shared -fPIC -o "$probe_dir/lib/arm64-v8a/libprobe.so" "$probe_dir/probe.c"
file "$probe_dir/lib/arm64-v8a/libprobe.so"

cat > "$probe_dir/Probe.java" <<'EOF'
package org.example.nativeprobe;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class Probe extends Activity {
    static { System.loadLibrary("probe"); }
    public native int value();

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        Log.i("NativeBridgeProbe", "loaded=" + value());
    }
}
EOF
cat > "$probe_dir/AndroidManifest.xml" <<'EOF'
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.example.nativeprobe">
    <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="28" />
    <application android:label="Native bridge probe">
        <activity android:name=".Probe" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
EOF

javac -source 8 -target 8 -cp "$android_jar" -d "$probe_dir/classes" "$probe_dir/Probe.java"
"$build_tools/d8" --lib "$android_jar" --output "$probe_dir" \
  "$probe_dir/classes/org/example/nativeprobe/Probe.class"
"$build_tools/aapt" package -f -M "$probe_dir/AndroidManifest.xml" \
  -I "$android_jar" -F "$probe_dir/unsigned.apk"
(
  cd "$probe_dir"
  zip -q unsigned.apk classes.dex lib/arm64-v8a/libprobe.so
)
"$build_tools/zipalign" -f 4 "$probe_dir/unsigned.apk" "$probe_dir/aligned.apk"
keytool -genkeypair -noprompt -alias probe -keyalg RSA -keysize 2048 \
  -validity 1 -keystore "$probe_dir/test.jks" -storepass probeonly \
  -keypass probeonly -dname 'CN=Native Bridge Probe' > /dev/null 2>&1
"$build_tools/apksigner" sign --ks "$probe_dir/test.jks" \
  --ks-pass pass:probeonly --key-pass pass:probeonly \
  --out "$probe_dir/probe.apk" "$probe_dir/aligned.apk"

adb -s "$serial" install "$probe_dir/probe.apk"
adb -s "$serial" logcat -c
adb -s "$serial" shell am start -W -n org.example.nativeprobe/.Probe
for attempt in $(seq 1 20); do
  logs=$(adb -s "$serial" logcat -d -s NativeBridgeProbe:I AndroidRuntime:E '*:S')
  if [[ "$logs" == *'NativeBridgeProbe: loaded=42'* ]]; then
    printf 'ARM64-only JNI library loaded and executed through native bridge\n'
    exit 0
  fi
  if [[ "$logs" == *'FATAL EXCEPTION'* ]]; then
    printf '%s\n' "$logs"
    exit 1
  fi
  sleep 1
done
printf '%s\n' "$logs"
exit 1
