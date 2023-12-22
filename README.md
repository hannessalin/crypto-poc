# crypto-poc
PoC implementations

## Installation of MCL on laboratory equipment
Go to [https://github.com/herumi/mcl](https://github.com/herumi/mcl) and follow the steps to install MCL. The following steps were taken when doing so:
- sudo apt install libgmp-dev
- sudo apt install clang
- git clone https://github.com/herumi/mcl
- cd mcl
- mkdir build
- cd build
- cmake .. -DCMAKE_CXX_COMPILER=clang++
- cd ..
- make
- pip install mcl
- The installation of mcl was set to /home/hsalin/mcl/mcl, therefore a path was needed: EXPORT MCL_PATH=/home/hsalin/mcl/mcl
