TARGET = rxe_send_mc

all: $(TARGET)

$(TARGET): $(TARGET).c

	gcc -g -Wall -D_GNU_SOURCE -g -O2 -o $(TARGET) $(TARGET).c -libverbs -lrdmacm -lpthread

clean: 
	rm $(TARGET)
