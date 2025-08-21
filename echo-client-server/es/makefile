TARGET=../bin/es
CPPFLAGS+=-Wall -O2
ifdef ANDROID_NDK_ROOT
LDFLAGS+=-static-libstdc++
endif
LDLIBS+=-pthread
#LDLIBS+=-lws2_32 # for mingw

all: $(TARGET)

$(TARGET): es.o
	$(LINK.cpp) $^ $(LOADLIBES) $(LDLIBS) -o $@
ifdef ANDROID_NDK_ROOT
	termux-elf-cleaner --api-level 23 $(TARGET)
	llvm-strip $(TARGET)
endif	

clean:
	rm -f $(TARGET) *.o

