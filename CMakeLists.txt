cmake_minimum_required(VERSION 3.0)
project(fast_ber_ldap3)

# Locate dependencies required from install path
find_package(absl REQUIRED)
find_package(fast_ber REQUIRED)

# Generate C++ header files from input ASN.1 file
fast_ber_generate(${CMAKE_CURRENT_SOURCE_DIR}/src/rfc-4511.asn1 rfc-4511)

# Create application executable, include generated files and fast_ber library
add_executable(ldap3_decoder src/ldap3_decoder.cpp ${CMAKE_CURRENT_BINARY_DIR}/autogen/rfc-4511.hpp)
target_include_directories(ldap3_decoder PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(ldap3_decoder fast_ber::fast_ber_lib)

# Test that ldap3_decoder can decode a ldap3 certificate
enable_testing()
add_test("Decode-LDAP" ldap3_decoder ${CMAKE_SOURCE_DIR}/testfiles/00000000)

