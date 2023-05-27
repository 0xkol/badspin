# Bad Spin: Android Binder LPE

Author: Moshe Kol

Privilege escalation exploit from `unstrusted_app` for Android Binder vulnerability (CVE-2022-20421). The vulnerability is patched on Android's Security Bulletin of October 2022. The exploit works on devices running kernel versions 5.4.x and 5.10.x, and it achieves full kernel R/W primitives. For the Google Pixel 6, it also obtains full root and SELinux bypass.

You can find the full write-up [here](https://0xkol.github.io/assets/files/Racing_Against_the_Lock__Exploiting_Spinlock_UAF_in_the_Android_Kernel.pdf).

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

## Support a new device

It is not difficult to adapt the exploit and support a new device.

1. Make sure your new device runs on kernel version 5.4.x or 5.10.x, and that its Android's security patch level is below October 2022.
2. Add your device properties to `dev_config.h`.
3. Specify two function pointers:
   * `kimg_to_lm()`: Converts a kernel image virtual pointer to the linear mapping. 
   * `find_kbase()`: Finding the kernel base address from an `anon_pipe_buf_ops` leaked pointer.
   
   You may use the already provided functions for this. (If your vendor is not Samsung and you're not sure, use the same functions as for the Pixel 6.)
4. Compile and run.

If it works for you, please submit a pull request.


## Known issues

* The phone might crash on unsuccessful attempts.
* The exploit is unstable in the first few minutes after boot.
* Only works on kernel versions 5.4.x and 5.10.x.
* Only achieves kernel R/W on non-Pixel devices.
