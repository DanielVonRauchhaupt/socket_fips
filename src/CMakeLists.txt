cmake_minimum_required(VERSION 3.18.4)

project(Bacherlorarbeit)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../external/tools/cmake)

include(ExternalProject)
ExternalProject_Add(libbpf
    PREFIX libbpf
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../external/libbpf/src
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make
        BUILD_STATIC_ONLY=1
        OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
        DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
        INCLUDEDIR=
        LIBDIR=
        UAPIDIR=
        install
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    STEP_TARGETS build
)

set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_SOURCE_DIR}/../tools/bpftool)
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/../vmlinux/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)
set(CMAKE_BUILD_TYPE RelWithDebInfo)
find_package(BpfObject REQUIRED)

include(ExternalProject)
ExternalProject_Add(hyperscan
    PREFIX hyperscan
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../external/hyperscan
    CMAKE_ARGS -DFAT_RUNTIME=false
)