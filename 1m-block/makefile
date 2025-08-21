all: 1m-block
	
1m-block:
	sudo iptables -F
	sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
	sudo iptables -A INPUT -j NFQUEUE --queue-num 0
	g++ -std=c++17 -O2 -o 1m-block 1m-block.cpp -lnetfilter_queue

run: 1m-block
	sudo ./1m-block top-1m.txt

clean:
	rm -f 1m-block
	rm -f index*
