
find_library(uring NAMES liburing PATH /usr/lib/x86_64-linux-gnu)

add_library(ip_hashtable STATIC ip_hashtable.c)
add_library(ip_to_str STATIC ip_to_str.c)
add_library(ip_llist STATIC ip_llist.c)
add_library(shm_ringbuf STATIC shm_ringbuf.c)
add_library(uring_getline uring_getline.c)

target_include_directories(uring_getline PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(ip_hashtable PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(ip_to_str PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(ip_llist PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(shm_ringbuf PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(uring_getline)
