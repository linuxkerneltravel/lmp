wget https://mirrors.tuna.tsinghua.edu.cn/gnu/gcc/gcc-8.1.0/gcc-8.1.0.tar.gz  --no-check-certificate
tar -zxvf gcc-8.1.0.tar.gz gcc-8.1.0/
cd gcc-8.1.0
./contrib/download_prerequisites
mkdir  build  &&  cd build
../configure -enable-checking=release -enable-languages=c,c++ -disable-multilib
make -j4 # wait 2-5 hours
sudo make install
