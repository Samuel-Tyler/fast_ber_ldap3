# fast_ber_ldap3 [![Travis status](https://travis-ci.org/Samuel-Tyler/fast_ber_ldap3.svg?branch=master)](https://travis-ci.org/Samuel-Tyler/fast_ber_ldap3) ![C++11](https://img.shields.io/badge/language-C%2B%2B11-green.svg) ![C++14](https://img.shields.io/badge/language-C%2B%2B14-green.svg) ![C++17](https://img.shields.io/badge/language-C%2B%2B17-green.svg) ![C++20](https://img.shields.io/badge/language-C%2B%2B20-green.svg)
Decode and inspect ldap3 certificates. A sample application demonstrating use of `fast_ber` with `cmake`.


## Usage
`fast_ber_ldap3` provides an application `ldap3_decoder` to decode and inspect the contents of a BER encoded ldap3 certificate. This application has been tested against the test certificates provided in the [PROTOS Test Suite](https://www.ee.oulu.fi/roles/ouspg/PROTOS_Test-Suite_c06-ldapv3).

```
$ ./build/ldap3_decoder testfiles/00000004 | jq .
{
  "messageID": 1,
  "protocolOp": {
    "baseObject": "",
    "scope": "wholeSubtree",
    "derefAliases": "neverDerefAliases",
    "sizeLimit": 0,
    "timeLimit": 0,
    "typesOnly": false,
    "filter": {
      "attributeDesc": "uid",
      "assertionValue": "Admin"
    },
    "attributes": []
  },
  "controls": null
}
```

## fast_ber CMake

`fast_ber_compiler` converts an ASN.1 schema into header files which are to be included by the user's application. The utility `fast_ber_generate` performs this translation. Input ASN.1 files and output name are provided as parameters to `fast_ber_generate`. Changes to the ASN.1 will cause the headers to be recompiled. `fast_ber_generate` is available in CMake after calling `find_package(fast_ber)`.

Below is the `CMakeLists.txt` used to create `ldap3_decoder`

```
# Locate dependencies required from install path
find_package(absl REQUIRED)
find_package(fast_ber REQUIRED)

# Generate C++ header files from input ASN.1 file
fast_ber_generate(${CMAKE_CURRENT_SOURCE_DIR}/src/rfc-4511.asn1 rfc-4511)

# Create application executable, include generated files and fast_ber library
add_executable(ldap3_decoder src/ldap3_decoder.cpp ${CMAKE_CURRENT_BINARY_DIR}/autogen/rfc-4511.hpp)
target_include_directories(ldap3_decoder PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(ldap3_decoder fast_ber::fast_ber_lib)
```

As `find_package` is used `fast_ber` and `abseil` must exist in the install location so they can be resolved when running cmake. 

Here are a set of commands which create an install directory then build `fast_ber` and `abseil` inside. Once this has completed the install folder will contain the header files, binaries and static libraries needed to create a project using `fast_ber`.

```
mkdir -p install

# Build and install abseil
mkdir -p build_abseil
cd build_abseil
cmake ../3rd_party/abseil-cpp -DCMAKE_INSTALL_PREFIX=../install
cmake --build . --target install

# Build and install fast_ber
mkdir -p build_fast_ber
cd build_fast_ber
cmake ../3rd_party/fast_ber -DCMAKE_INSTALL_PREFIX=../install -DSKIP_TESTING=true -DSKIP_AUTO_GENERATION=true
cmake --build . --target install
```

Finally, `cmake` is run on the target project referencing the install location. Dependencies are picked up and linked into the `ldap3_decoder` application.
```
# Build and test ldap3_decoder, provide install path to locate fast_ber and abseil
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=../install
cmake --build .
```
