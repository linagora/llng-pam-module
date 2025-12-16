# CMakeLists.txt for libnss_llng

# NSS library
add_library(nss_llng SHARED libnss_llng.c)

target_include_directories(nss_llng PRIVATE
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(nss_llng
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    pthread
)

# NSS modules have specific naming convention: libnss_NAME.so.2
set_target_properties(nss_llng PROPERTIES
    OUTPUT_NAME "nss_llng"
    VERSION 2
    SOVERSION 2
    PREFIX "lib"
)

# Compiler flags
target_compile_options(nss_llng PRIVATE
    -Wall -Wextra -fPIC
    -D_GNU_SOURCE
)

# Install NSS module to the same libdir as PAM module
install(TARGETS nss_llng
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Install config file template
install(FILES nss_llng.conf.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}
)
