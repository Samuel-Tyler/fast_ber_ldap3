mkdir -p build
mkdir -p build_abseil
mkdir -p build_fast_ber
mkdir -p install

# Build and install abseil
cd build_abseil
cmake ../3rd_party/abseil-cpp -DCMAKE_INSTALL_PREFIX=../install
cmake --build . --target install
cd ..

# Build and install fast_ber
cd build_fast_ber
cmake ../3rd_party/fast_ber -DCMAKE_INSTALL_PREFIX=../install -DSKIP_TESTING=true -DSKIP_AUTO_GENERATION=true
cmake --build . --target install
cd ..

# Build and test ldap3_decoder
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=../install
cmake --build .
ctest
