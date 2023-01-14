cmake_minimum_required(VERSION 3.0.0)


set(TRACERT_PROJECT_NAME
    traceroute
)

set(TRACERT_SOURCE_DIR
    src
)

set(TRACERT_SOURCE
    ${TRACERT_SOURCE_DIR}/main.c
)

set(TRACERT_LIBRARIES_DIR
    libs
)

set(TRACERT_LIBRARIES
    utils
)

project(${TRACERT_PROJECT_NAME})

add_executable(${TRACERT_PROJECT_NAME} ${TRACERT_SOURCE})

foreach(LIBRARY ${TRACERT_LIBRARIES})
    add_subdirectory("${TRACERT_LIBRARIES_DIR}/${LIBRARY}")
endforeach(LIBRARY)

target_link_libraries(${TRACERT_PROJECT_NAME} ${TRACERT_LIBRARIES})