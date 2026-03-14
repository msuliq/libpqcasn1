cmake_minimum_required(VERSION 3.14)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" PQC_ASN1_VERSION)
string(STRIP "${PQC_ASN1_VERSION}" PQC_ASN1_VERSION)

project(pqc_asn1
  VERSION ${PQC_ASN1_VERSION}
  LANGUAGES C
  DESCRIPTION "Standalone DER/PEM/Base64 codec for post-quantum key serialization"
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Library target (static by default, BUILD_SHARED_LIBS=ON for shared)
add_library(pqc_asn1
  src/pqc_asn1.c
)
target_include_directories(pqc_asn1
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_options(pqc_asn1 PRIVATE
  $<$<C_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wshadow -Wpedantic>
  $<$<C_COMPILER_ID:MSVC>:/W4>
)
target_compile_options(pqc_asn1 PRIVATE
  $<$<AND:$<CONFIG:Release>,$<C_COMPILER_ID:GNU,Clang,AppleClang>>:-O2>
  $<$<AND:$<CONFIG:Release>,$<C_COMPILER_ID:MSVC>>:/O2>
  $<$<AND:$<CONFIG:RelWithDebInfo>,$<C_COMPILER_ID:GNU,Clang,AppleClang>>:-O2 -g>
  $<$<AND:$<CONFIG:RelWithDebInfo>,$<C_COMPILER_ID:MSVC>>:/O2 /Zi>
  $<$<AND:$<CONFIG:Debug>,$<C_COMPILER_ID:GNU,Clang,AppleClang>>:-O0 -g>
  $<$<AND:$<CONFIG:Debug>,$<C_COMPILER_ID:MSVC>>:/Od /Zi>
)
set_target_properties(pqc_asn1 PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  PUBLIC_HEADER include/pqc_asn1.h
)

# Install rules
include(GNUInstallDirs)
install(TARGETS pqc_asn1
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# pkg-config
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/pqc_asn1.pc.in
  ${CMAKE_CURRENT_BINARY_DIR}/pqc_asn1.pc
  @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pqc_asn1.pc
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# Tests
option(PQC_ASN1_BUILD_TESTS "Build tests" ON)
if(PQC_ASN1_BUILD_TESTS)
  enable_testing()
  add_executable(test_pqc_asn1 test/test_pqc_asn1.c)
  target_link_libraries(test_pqc_asn1 PRIVATE pqc_asn1)
  add_test(NAME test_pqc_asn1 COMMAND test_pqc_asn1)
endif()
