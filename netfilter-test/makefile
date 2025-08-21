all: netfilter-test

netfilter-test:
	sudo iptables -F
	sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
	sudo iptables -A INPUT -j NFQUEUE --queue-num 0
	gcc -o netfilter-test netfilter-test.c -lnetfilter_queue

run: netfilter-test
	sudo ./netfilter-test test.gilgil.net

clean:
	rm -f netfilter-test
	rm -f index*
