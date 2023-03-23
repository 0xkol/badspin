LIBNAME=badspin

ifndef ANDROID_NDK_HOME
$(error ANDROID_NDK_HOME is not set)
endif

ARCH=aarch64
TOOLCHAIN=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64
TARGET=$(ARCH)-linux-android
API=30

CC=$(TOOLCHAIN)/bin/$(TARGET)$(API)-clang
CXX=$(TOOLCHAIN)/bin/$(TARGET)$(API)-clang++

LIBSEPOL_DIR=libsepol
APP_DIR=../app

TEST_VULN ?= 0
VERBOSE ?= 0

CCFLAGS += -Wall
CCFLAGS += -pthread
CCFLAGS += -Wno-unused-variable
CCFLAGS += -Wno-unused-function
CCFLAGS += -DTEST_VULN=$(TEST_VULN)
CCFLAGS += -DVERBOSE=$(VERBOSE)
CCFLAGS += -I$(LIBSEPOL_DIR)/include

OBJ += exploit.o
OBJ += vuln.o
OBJ += util.o
OBJ += uao.o
OBJ += rw.o
OBJ += ksym.o
OBJ += unix.o
OBJ += binder_client.o
OBJ += light_cond.o
OBJ += token_manager.o
OBJ += sepolicy.o
OBJ += root.o


.PHONY: all
all: clean $(LIBSEPOL_DIR)/src/libsepol.a lib$(LIBNAME).so
	@echo "\n[x] lib$(LIBNAME).so successfully generated."

list: list_devices
	@./list_devices

list_devices:
	gcc -Wall -Wno-unused-variable -DLIST_DEVICES -o list_devices -x c dev_config.h

lib$(LIBNAME).so: $(OBJ)
	$(CC) $(CCFLAGS) -shared -o $@ $^ $(LIBSEPOL_DIR)/src/libsepol.a -llog

%.o: %.c
	$(CC) $(CCFLAGS) -c -fpic -o $@ -c $<

$(LIBSEPOL_DIR)/src/libsepol.a:
	CC=$(CC) PREFIX=.. DISABLE_CIL=y make -C $(LIBSEPOL_DIR)/src libsepol.a

.PHONY: push
push: all
	@echo "\n[x] Push lib to device"
	adb push lib$(LIBNAME).so /data/local/tmp
	@echo "\n[x] Copy lib to app's assets"
	cp lib$(LIBNAME).so $(APP_DIR)/app/src/main/assets/

.PHONY: clean
clean:
	rm -rf $(OBJ) lib$(LIBNAME).so list_devices