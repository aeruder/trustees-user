CFLAGS += -ggdb -I$(PWD)/../include -Wall
LDFLAGS := 
CC := gcc
settrustees_objs := settrustees.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

default: settrustees

settrustees: $(settrustees_objs)
	gcc $(LDFLAGS) -o settrustees $(settrustees_objs) 

clean:
	rm -fr *.o settrustees
