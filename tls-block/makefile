CXX = g++
CXXFLAGS = -Wall -O2
LDFLAGS = -lpcap -lnet

TARGET = tls-block
OBJS = tls-block.cpp mac.cpp

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
