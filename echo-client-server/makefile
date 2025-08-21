.PHONY: all ec es clean install uninstall android-install android-uninstall

BIN_DIR = bin
EC_BIN = $(BIN_DIR)/ec
ES_BIN = $(BIN_DIR)/es

CXX = g++
CXXFLAGS = -std=c++11 -pthread
EC_SRC = ec/ec.cpp
ES_SRC = es/es.cpp

all: ec es

ec: $(EC_BIN)

$(EC_BIN): $(EC_SRC)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<

es: $(ES_BIN)

$(ES_BIN): $(ES_SRC)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -rf $(BIN_DIR)

install:
	sudo cp $(EC_BIN) /usr/local/sbin
	sudo cp $(ES_BIN) /usr/local/sbin

uninstall:
	sudo rm -f /usr/local/sbin/ec /usr/local/sbin/es

android-install:
	adb push $(EC_BIN) $(ES_BIN) /data/local/tmp
	adb exec-out "su -c 'mount -o rw,remount /system'"
	adb exec-out "su -c 'cp /data/local/tmp/ec /data/local/tmp/es /system/xbin'"
	adb exec-out "su -c 'chmod 755 /system/xbin/ec /system/xbin/es'"
	adb exec-out "su -c 'mount -o ro,remount /system'"
	adb exec-out "su -c 'rm /data/local/tmp/ec /data/local/tmp/es'"

android-uninstall:
	adb exec-out "su -c 'mount -o rw,remount /system'"
	adb exec-out "su -c 'rm /system/xbin/ec /system/xbin/es'"
	adb exec-out "su -c 'mount -o ro,remount /system'"


