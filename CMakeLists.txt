cmake_minimum_required(VERSION 3.18.4)

project(Bacherlorarbeit)
# set(CMAKE_CXX_COMPILER "clang++")


# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/external/tools/cmake)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)

# set(CMAKE_CXX_COMPILER "g++")
# set(CMAKE_C_COMPILER "gcc")



# External libraries
add_subdirectory(external)

# Local libraries
add_subdirectory(src/lib)

# System dependencies (liburing and pthread)
find_library(uring NAMES liburing PATHS /usr/lib/x86_64-linux-gnu)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# Global compile options
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
    # Trying to add new file to include. I hope this works
    PUBLIC sock_comm
    PUBLIC uring
)
# For sanitizer; Might want to remove this later
target_compile_options(udp_server PRIVATE -fsanitize=address)
target_link_options(udp_server PRIVATE -fsanitize=address)

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

# SimpleLogstash_4socks Programm
add_executable(simplelogstash_4socks ${CMAKE_CURRENT_SOURCE_DIR}/src/programs/simplelogstash_4socks.c)

target_include_directories(simplelogstash_4socks
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include
)

target_link_libraries(simplelogstash_4socks 
    PUBLIC Threads::Threads
    PUBLIC sock_comm
    PUBLIC uring
)

#nsyslog
add_executable(nsyslog ${CMAKE_CURRENT_SOURCE_DIR}/src/programs/nsyslog.c)

target_include_directories(nsyslog
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include
)

target_link_libraries(nsyslog 
    PUBLIC Threads::Threads
    PUBLIC shm_ringbuf
    PUBLIC uring
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
# add_executable(simplefail2ban_signer ${CMAKE_CURRENT_SOURCE_DIR}/src/programs/simplefail2ban_signer.c)
# add_executable(test_grpc ${CMAKE_CURRENT_SOURCE_DIR}/src/programs/test_grpc.c)                                                         



target_include_directories(simplefail2ban
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/external/libbpf/src            
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
    # Trying to add new file to include. I hope this works
    PUBLIC sock_comm
    PUBLIC hs
    PUBLIC uring
    PUBLIC Threads::Threads
    )

# include_directories("/root/.local/include/")
# include_directories("/mnt/scratch/signer/fips/ips-action/src/")

# target_include_directories(simplefail2ban_signer
#     PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/external/libbpf/src            
#     PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include
#     PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/programs
#     PUBLIC /usr/include/hs
#     PUBLIC /mnt/scratch/signer/fips/ips-action/src
# ) 

# target_include_directories(test_grpc
#     PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/external/libbpf/src            
#     PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include
#     PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/programs
#     PUBLIC /usr/include/hs
#     PUBLIC /mnt/scratch/signer/fips/ips-action/src
# )

# target_link_libraries(simplefail2ban_signer
#     PUBLIC stdc++
#     PUBLIC stdc++
#     PUBLIC ebpf_utils
#     PUBLIC uring_getline
#     PUBLIC ip_hashtable
#     PUBLIC ip_llist
#     PUBLIC ip_to_str
#     PUBLIC shm_ringbuf
#     PUBLIC hs
#     PUBLIC uring
#     PUBLIC Threads::Threads
#     "/mnt/scratch/signer/fips/ips-action/build/src/libfips_grpc.so"
# )

# target_link_libraries(test_grpc
#     "/mnt/scratch/signer/fips/ips-action/build/src/libfips_grpc.so")


# Poll_rbuf utility
add_executable(poll_rbuf ${CMAKE_CURRENT_SOURCE_DIR}/src/utilities/poll_rbuf.c)
target_include_directories(poll_rbuf
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include
)

target_link_libraries(poll_rbuf 
    PUBLIC shm_ringbuf
    PUBLIC Threads::Threads
)

# Benchmarks
add_executable(ip_string_benchmark ${CMAKE_CURRENT_SOURCE_DIR}/src/utilities/ip_string_benchmark.c)
target_include_directories(ip_string_benchmark
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include
)

target_link_libraries(ip_string_benchmark 
    PUBLIC ip_to_str
)

# Benchmarks
add_executable(hashfunc_benchmark ${CMAKE_CURRENT_SOURCE_DIR}/src/utilities/hashfunc_benchmark.c)
target_include_directories(hashfunc_benchmark
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include
)

target_link_libraries(hashfunc_benchmark 
    PUBLIC ip_hashtable
)
