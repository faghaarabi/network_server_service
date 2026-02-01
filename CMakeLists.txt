cmake_minimum_required(VERSION 3.20)
project(network_server_service C)

set(CMAKE_C_STANDARD 11)

# Library for DB helpers
add_library(user_db
        src/user_db.c
)
target_include_directories(user_db PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Main server app (name must NOT be "server" because you have server/ dir)
add_executable(server_app
        main.c
)
target_link_libraries(server_app PRIVATE user_db)

# Optional: db_test executable
add_executable(db_test
        src/db_test.c
)
target_link_libraries(db_test PRIVATE user_db)
