cmake_minimum_required(VERSION 3.0)
project(fast_ber_ldap3)

# Setup Conan if enabled
if (EXISTS "${CMAKE_SOURCE_DIR}/conanbuildinfo.cmake")
    include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    conan_basic_setup()
endif()

# Locate dependencies required from install path
find_package(absl REQUIRED CONFIG)
find_package(fast_ber REQUIRED CONFIG)

# Generate C++ header files from input ASN.1 file
fast_ber_generate(${CMAKE_CURRENT_SOURCE_DIR}/src/rfc-4511.asn1 rfc-4511)

# Create ldap3_decoder executable, include generated files and fast_ber library
add_executable(ldap3_decoder src/ldap3_decoder.cpp ${CMAKE_CURRENT_BINARY_DIR}/autogen/rfc-4511.hpp)
target_include_directories(ldap3_decoder PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(ldap3_decoder fast_ber::fast_ber_lib)

# Create ldap3_encoder executable, include generated files and fast_ber library
add_executable(ldap3_encoder src/ldap3_encoder.cpp ${CMAKE_CURRENT_BINARY_DIR}/autogen/rfc-4511.hpp)
target_include_directories(ldap3_encoder PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(ldap3_encoder fast_ber::fast_ber_lib)

# Test that certificate can be encoded / decoded
enable_testing()
add_test("Encode-LDAP" ldap3_encoder test.ber)
add_test("Decode-LDAP" ldap3_decoder ${CMAKE_SOURCE_DIR}/testfiles/00000000)

