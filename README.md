# Bad Spin: Android Binder LPE

Author: Moshe Kol

Privilege escalation exploit from `unstrusted_app` for Android Binder vulnerability (CVE-2022-20421). The vulnerability is patched on Android's Security Bulletin of October 2022.

## Run from shell

1. Compile the `libbadspin.so` library by typing `make push` in the `src/` directory. This will also push the library to `/data/local/tmp`.
2. Run `adb shell`.
3. Run `LD_PRELOAD=/data/local/tmp/libbadspin.so sleep 1`. This will load the library and start the exploit.

## Run from demo app

1. Compile `libbadspin.so` by typing `make push` in the `src/` directory. This will copy the library to the `assets` directory for the demo Android app.
2. Compile the demo Android app in the `app/` directory. (You might need Android Studio to do this.)
3. Run the app and click on the "Exploit" button. 
4. Consume logs using: `adb logcat -s BADSPIN`

## Compilation options

You can pass the following variables to `make`:

- `VERBOSE=1` to increase verbosity.
- `TEST_VULN=1` to test the vulnerability without proceeding with the exploit.

## Tested devices

```
$ make list
0: Samsung Galaxy S22, Android 12 (6/2022), kernel 5.10.81
1: Samsung Galaxy S21 Ultra, Android 12 (3/2022), kernel 5.4.129
2: Google Pixel 6, Android 12 (5/2022), kernel 5.10.66
3: Google Pixel 6, Android 13 (9/2022), kernel 5.10.107
```

Full root and SELinux bypass for Pixel 6. For Samsung devices, the exploit achieves kernel R/W only.

## Known issues

The phone might crash on unsuccessful attempts. The exploit is unstable in the first few minutes after boot.