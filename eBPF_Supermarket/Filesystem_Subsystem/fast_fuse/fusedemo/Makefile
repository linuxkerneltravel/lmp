cd eBPF_Supermarket/Filesystem_Subsystem/fast_fuse/fusedemo/
sudo apt updata
sudo apt install fuse libfuse-dev meson ninja wget
git clone https://github.com/libfuse/libfuse/releases/tag/fuse-3.16.2/fuse-3.16.2.tar.gz
tar -zxvf fuse-3.16.2.tar.gz
mv fuse-3.16.2.tar.gz libfuse
cd libfuse
mkdir build
cd build
meson ..
meson configure -D disable-mtab=true
ninja
sudo ninja install