rm ./build
mkdir ./build
cd ./build
meson ../
meson configure -D disable-mtab=true
ninja
sudo ninja install
