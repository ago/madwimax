CC := gcc
CFLAGS := -g -Wall
LDFLAGS :=
SOURCES := src/protocol.c src/tap_dev.c src/wimax.c
OBJECTS := $(SOURCES:.c=.o)
LIBS := -lusb-1.0 -lpthread
EXECUTABLE := wimax

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $(EXECUTABLE) $(OBJECTS) $(LIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

.PHONY: clean all

clean:
	rm -f $(EXECUTABLE) src/*.o src/*.d

