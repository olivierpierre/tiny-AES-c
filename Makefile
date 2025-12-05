#CC           = avr-gcc
#CFLAGS       = -Wall -mmcu=atmega16 -Os -Wl,-Map,test.map
#OBJCOPY      = avr-objcopy
CC           = gcc
LD           = gcc
AR           = ar
ARFLAGS      = rcs
CFLAGS       = -Wall -Os -c -fsanitize=address -g
LDFLAGS      = -Wall -Os -fsanitize=address -Wl,-Map,test.map
ifdef AES192
CFLAGS += -DAES192=1
endif
ifdef AES256
CFLAGS += -DAES256=1
endif

OBJCOPYFLAGS = -j .text -O ihex
OBJCOPY      = objcopy

# include path to AVR library
INCLUDE_PATH = /usr/lib/avr/include
# splint static check
SPLINT       = splint test.c aes.c -I$(INCLUDE_PATH) +charindex -unrecog

default: aes-comp

# .SILENT:
.PHONY:  lint clean

aes-comp.o: aes-comp.c aes-comp.h aes.h
	$(CC) $(CFLAGS) -o $@ $<

aes-comp: aes-comp.o aes.o
	$(CC) $^ -o $@ $(LDFLAGS)

aes-comp-client.o: aes-comp-client.c aes-comp.h
	$(CC) $(CFLAGS) -o $@ $<

test.hex : test.elf
	echo copy object-code to new image and format in hex
	$(OBJCOPY) ${OBJCOPYFLAGS} $< $@

test.o : test.c aes.h aes-comp-client.h aes.o aes-comp-client.h
	echo [CC] $@ $(CFLAGS)
	$(CC) $(CFLAGS) -o  $@ $<

benchmark.o : benchmark.c aes.h aes-comp-client.h aes.o aes-comp-client.h
	echo [CC] $@ $(CFLAGS)
	$(CC) $(CFLAGS) -o  $@ $<

aes.o : aes.c aes.h
	echo [CC] $@ $(CFLAGS)
	$(CC) $(CFLAGS) -o $@ $<

benchmark-comp: aes-comp-client.o benchmark.o
	echo [LD] $@
	$(LD) $(LDFLAGS) -o $@ $^

benchmark-native: aes.o benchmark.o
	echo [LD] $@
	$(LD) $(LDFLAGS) -o $@ $^

test.elf : aes-comp-client.o test.o
	echo [LD] $@
	$(LD) $(LDFLAGS) -o $@ $^

aes.a : aes.o
	echo [AR] $@
	$(AR) $(ARFLAGS) $@ $^

lib : aes.a

clean:
	rm -f *.OBJ *.LST *.o *.gch *.out *.hex *.map *.elf *.a benchmark-comp \
		benchmark-native aes-comp

test:
	make clean && make && ./test.elf
	make clean && make AES192=1 && ./test.elf
	make clean && make AES256=1 && ./test.elf

lint:
	$(call SPLINT)
