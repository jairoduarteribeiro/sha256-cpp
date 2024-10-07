find_package(OpenSSL REQUIRED)

add_executable(sha256 main.cpp)
target_link_libraries(sha256 PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(sha256 PRIVATE ${OPENSSL_INCLUDE_DIR})
