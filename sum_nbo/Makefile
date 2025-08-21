all: sum-nbo

sum-nbo: main.o sum_nbo.o
	g++ -o sum-nbo main.o sum_nbo.o

main.o: sum_nbo.h main.cpp
	g++ -c -o main.o main.cpp

sum_nbo.o: sum_nbo.h sum_nbo.cpp
	g++ -c -o sum_nbo.o sum_nbo.cpp

clean:
	rm -f sum-nbo
	rm -f *.o
