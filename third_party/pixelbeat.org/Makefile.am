.PHONY : clean all install

CFLAGS = -fPIC
LDFLAGS = -shared

SOURCES = string_replace.c
OBJECTS = $(SOURCES:.c=.o)

TARGET = libstring_replace.so

all: $(TARGET)

$(TARGET) : $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

$(SOURCES:.c=.o):%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

install:
	install -m 0755 libstring_replace.so  $(prefix)/usr/lib
