all: tcp-block

tcp-block : main.o
	g++ -o tcp-block main.o -lpcap
main.o : main.cpp
	g++ -c -o main.o main.cpp
clean :
	rm -f tcp-block *.o

