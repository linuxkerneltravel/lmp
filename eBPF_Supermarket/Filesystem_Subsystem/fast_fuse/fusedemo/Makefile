.PHONY: all configure build install clean

all: configure build install

configure:
	mkdir -p build
	cd build && meson ../
	cd build && meson configure -D disable-mtab=true

build:
	cd build && ninja

install:
	cd build && sudo ninja install

clean:
	rm -rf build