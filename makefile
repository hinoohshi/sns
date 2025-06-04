CXX = g++
CXXFLAGS = -Wall -O2
LDFLAGS = -lpcap -lnet

TARGET = tcp-block
OBJS = tcp-block.cpp mac.cpp

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
