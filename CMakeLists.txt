cmake_minimum_required(VERSION 3.18.4)

project(Bacherlorarbeit)

# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/external/tools/cmake)

add_subdirectory(external)

add_subdirectory(src/lib)

add_executable(udp_server src/programs/udp_server.c)

target_compile_options(udp_server PRIVATE -Wall -Wextra -Wpedantic)

target_include_directories(udp_server
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include
)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

target_link_libraries(udp_server 
    PUBLIC ringbuf
    PUBLIC ip_hashtable
    PUBLIC ip_to_str
    PUBLIC Threads::Threads
)

# Set BpfObject input parameters -- note this is usually not necessary unless
# you're in a highly vendored environment (like libbpf-bootstrap)
set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/external/bpftool/bootstrap/bpftool)
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/external/vmlinux/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/external/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/external/libbpf/libbpf.a)
find_package(BpfObject REQUIRED)

# Build object skeleton and depend skeleton on libbpf build
bpf_object(ip_blacklist ip_blacklist.bpf.c)
add_dependencies(ip_blacklist_skel libbpf-build bpftool)
add_library(blacklist_common STATIC ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/blacklist_common.c)
target_include_directories(blacklist_common PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/external/libbpf)
add_dependencies(blacklist_common libbpf-build)

add_executable(simplefail2ban ${CMAKE_CURRENT_SOURCE_DIR}/src/programs/simplefail2ban.c)

target_compile_options(simplefail2ban PRIVATE -Wall -Wextra -Wpedantic)

add_dependencies(simplefail2ban libbpf-build)
add_dependencies(simplefail2ban inih)
add_dependencies(simplefail2ban llist)
target_include_directories(simplefail2ban
    #PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/external/hyperscan/src
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/external/libbpf/src      
    PUBLIC /usr/include/hs          
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/external/list/src  
) 
target_link_libraries(simplefail2ban ip_blacklist_skel ringbuf ip_hashtable ip_to_str hs blacklist_common inih llist) 