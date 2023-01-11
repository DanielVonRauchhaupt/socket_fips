cmake_minimum_required(VERSION 3.18.4)

project(Bacherlorarbeit)

set(FAT_RUNTIME OFF CACHE BOOL "Build a library that supports multiple microarchitectures" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "Build Hyperscan example code (default TRUE)" FORCE)

add_subdirectory(external/hyperscan)

add_subdirectory(external/ip_blacklist/src)

add_subdirectory(src/lib)

add_executable(udp_server src/programs/udp_server.c)

target_include_directories(udp_server
    PUBLIC src/lib/include
)

target_link_libraries(udp_server 
    PUBLIC ringbuf
    PUBLIC atomic_hashtable
    PUBLIC ip_to_str
)

add_executable(simplefail2ban src/programs/simplefail2ban.c)

set_property(TARGET simplefail2ban PROPERTY ENABLE_EXPORTS 1)

target_include_directories(simplefail2ban
    PUBLIC external/hyperscan/src
    PUBLIC external/ip_blacklist/src
    PUBLIC external/ip_blacklist/libbpf/src
    PUBLIC src/lib/include
)


target_link_libraries(simplefail2ban 
    PUBLIC hs
    PUBLIC libbpf
    PUBLIC ip_to_str
    PUBLIC ringbuf
    PUBLIC atomic_hashtable
)



