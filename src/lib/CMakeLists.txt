
add_library(ringbuf STATIC ringbuf.c)
add_library(ip_to_str STATIC ip_to_str.c)
add_library(ip_llist STATIC ip_llist.c)

target_include_directories(ringbuf PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(ip_to_str PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(ip_llist PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
