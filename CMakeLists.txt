cmake_minimum_required(VERSION 3.18.4)

project(Bacherlorarbeit)

# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/external/tools/cmake)

# External libraries
add_subdirectory(external)

# Local libraries
add_subdirectory(src/lib)

# System dependencies (liburing and pthread)
find_library(uring NAMES liburing PATHS /usr/lib/x86_64-linux-gnu)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_compile_options(-Wall -Wextra -pedantic -O2)

# UDP Server Programm
add_executable(udp_server ${CMAKE_CURRENT_SOURCE_DIR}/src/programs/udp_server.c)
target_include_directories(udp_server
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include
)
target_link_libraries(udp_server
    PUBLIC ip_to_str
    PUBLIC Threads::Threads
    PUBLIC shm_ringbuf
    PUBLIC uring
)

# SimpleLogstash Programm
add_executable(simplelogstash ${CMAKE_CURRENT_SOURCE_DIR}/src/programs/simplelogstash.c)

target_include_directories(simplelogstash
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include
)

target_link_libraries(simplelogstash 
    PUBLIC Threads::Threads
    PUBLIC shm_ringbuf
    PUBLIC uring
)

# Poll_rbuf utility
add_executable(poll_rbuf ${CMAKE_CURRENT_SOURCE_DIR}/src/programs/poll_rbuf.c)
target_include_directories(poll_rbuf
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include
)

target_link_libraries(poll_rbuf 
    PUBLIC shm_ringbuf
    PUBLIC Threads::Threads
)

# BPF Setup
set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/external/bpftool/bootstrap/bpftool)
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/external/vmlinux/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/external/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/external/libbpf/libbpf.a)
find_package(BpfObject REQUIRED)

bpf_object(ip_blacklist ip_blacklist.bpf.c)
add_dependencies(ip_blacklist_skel libbpf-build bpftool)

add_library(ebpf_utils ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/ebpf_utils.c)

target_include_directories(ebpf_utils 
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/external/libbpf/src    )

target_link_libraries(ebpf_utils ip_blacklist_skel)

# SimpleFail2ban Programm
add_executable(simplefail2ban ${CMAKE_CURRENT_SOURCE_DIR}/src/programs/simplefail2ban.c)                                                         

target_include_directories(simplefail2ban
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/external/libbpf/src            
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/external/list/src  
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/programs
    PUBLIC /usr/include/hs
) 

target_link_libraries(simplefail2ban
    PUBLIC ebpf_utils
    PUBLIC uring_getline
    PUBLIC ip_hashtable
    PUBLIC ip_llist
    PUBLIC ip_to_str
    PUBLIC shm_ringbuf
    PUBLIC hs
    PUBLIC uring
    PUBLIC Threads::Threads) 
