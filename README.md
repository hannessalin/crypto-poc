# crypto-poc
PoC implementations

## Installation of MCL on laboratory equipment
Go to [https://github.com/herumi/mcl](https://github.com/herumi/mcl) and follow the steps to install MCL. The following steps were taken when doing so:
- sudo apt install libgmp-dev
- sudo apt install clang
- git clone https://github.com/herumi/mcl
- cd mcl
- mkdir build
- cmake -DCMAKE_CXX_COMPILER=clang++ .
