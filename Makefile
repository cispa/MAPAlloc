
all:
	$(MAKE) -C migrator
	$(MAKE) -C module
	$(MAKE) -C utils

clean:
	$(MAKE) -C migrator clean
	$(MAKE) -C module clean
	$(MAKE) -C utils clean
	rm -f .*.cmd *.order
