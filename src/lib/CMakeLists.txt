
add_library(ringbuf STATIC ringbuf.c)
add_library(ip_to_str STATIC ip_to_str.c)
add_library(atomic_hashtable STATIC atomic_hashtable.c)

target_include_directories(ringbuf PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(ip_to_str PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(atomic_hashtable PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)