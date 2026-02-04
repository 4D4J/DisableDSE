cmake_minimum_required(VERSION 3.10.0)
project(DSE_bypass VERSION 0.1.0 LANGUAGES C CXX)

# Static runtime linking to avoid DLL dependencies
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(DSE_bypass dse_bypass.cpp)

# Force static linking of the runtime
if(MSVC)
    set_property(TARGET DSE_bypass PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_options(DSE_bypass PRIVATE
        $<$<CONFIG:Release>:/MT>
        $<$<CONFIG:Debug>:/MTd>
    )
endif()

# Link libraries
target_link_libraries(DSE_bypass ntdll shlwapi)

