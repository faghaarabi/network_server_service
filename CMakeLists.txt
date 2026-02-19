cmake_minimum_required(VERSION 3.16)
project(network_server_service C)

set(CMAKE_C_STANDARD 11)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(server_app
  main.c
  protocol.c
  src/user_db.c
)

find_package(Threads REQUIRED)
target_link_libraries(server_app Threads::Threads)

if (EXISTS "${CMAKE_SOURCE_DIR}/src/db_test.c")
  add_executable(db_test
    src/db_test.c
    src/user_db.c
  )
  target_link_libraries(db_test Threads::Threads)
endif()
