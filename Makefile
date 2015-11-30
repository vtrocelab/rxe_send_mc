TARGET1 = mckey
TARGET2 = rxe_send_mc

all: $(TARGET1) $(TARGET2)

$(TARGET1): $(TARGET2).c
$(TARGET1): $(TARGET2).c

	gcc -g -Wall -D_GNU_SOURCE -g -O2 -o $(TARGET1) $(TARGET1).c -libverbs -lrdmacm -lpthread
	gcc -g -Wall -D_GNU_SOURCE -g -O2 -o $(TARGET2) $(TARGET2).c -libverbs -lrdmacm -lpthread

clean: 
	rm $(TARGET1)
	rm $(TARGET2)
