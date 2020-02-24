cmake_minimum_required(VERSION 3.0)
project(fast_ber_ldap3)

find_package(absl REQUIRED)
find_package(fast_ber REQUIRED)

fast_ber_generate(${CMAKE_CURRENT_SOURCE_DIR}/src/rfc-4511.asn1 rfc-4511)

add_executable(ldap3_decoder src/ldap3_decoder.cpp ${CMAKE_CURRENT_BINARY_DIR}/autogen/rfc-4511.hpp)
target_include_directories(ldap3_decoder PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(ldap3_decoder fast_ber::fast_ber_lib)

enable_testing()
add_test("Decode-LDAP" ldap3_decoder ${CMAKE_SOURCE_DIR}/testfiles/00000000)

