# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
cmake_minimum_required(VERSION 3.18)

set(FAT_RUNTIME OFF CACHE BOOL "Build a library that supports multiple microarchitectures" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "Build Hyperscan example code (default TRUE)" FORCE)


# Build vendored libbpf
include(ExternalProject)
ExternalProject_Add(libbpf
  PREFIX libbpf
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make
    BUILD_STATIC_ONLY=1
    OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
    DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
    INCLUDEDIR=
    LIBDIR=
    UAPIDIR=
    install install_uapi_headers
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

ExternalProject_Add(bpftool
  PREFIX bpftool
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make bootstrap
    OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

ExternalProject_Add(hyperscan
  PREFIX hyperscan
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/hyperscan
  CMAKE_ARGS -DFAT_RUNTIME=OFF -DBUBUILD_EXAMPLES=OFF
  INSTALL_COMMAND ""
)

