all: recvSelect sendMultConnect

recvSelect: recvSelect.c
	gcc -pthread -pedantic -Wall -Wextra $^ -o $@

sendMultConnect: sendMultConnect.c
	gcc -pthread -pedantic -Wall -Wextra $^ -o $@


.phony: clean

clean: 
	rm -f recvSelect *.o
	rm -f sendMultConnect *.o