cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(arch_arcompact)

file(GLOB SOURCES
	*.cpp
	*.h
	arcompact/*.cpp
	arcompact/*.h)

add_library(${PROJECT_NAME} SHARED ${SOURCES})

find_path(
    BN_API_PATH
    NAMES binaryninjaapi.h
    HINTS ../.. binaryninjaapi $ENV{BN_API_PATH}
    REQUIRED
)
add_subdirectory(${BN_API_PATH} api)

target_include_directories(${PROJECT_NAME}
	PRIVATE ${PROJECT_SOURCE_DIR}
	PRIVATE ${PROJECT_SOURCE_DIR}/arcompact)

target_link_libraries(${PROJECT_NAME} binaryninjaapi)

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
	C_STANDARD 99
	C_STANDARD_REQUIRED ON
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

bn_install_plugin(${PROJECT_NAME})