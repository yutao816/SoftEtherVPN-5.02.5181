cmake_minimum_required(VERSION 3.0)
project(mqtt_vpn C)

# 查找必要的库
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# 添加可执行文件
add_executable(mqtt_vpn mqtt_vpn.c)

# 包含头文件目录
target_include_directories(mqtt_vpn PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# 链接必要的库
target_link_libraries(mqtt_vpn PRIVATE
    ${OPENSSL_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    paho-mqtt3c
    nacl
)

# 设置编译选项
target_compile_options(mqtt_vpn PRIVATE -Wall -Wextra)

# 安装目标
install(TARGETS mqtt_vpn DESTINATION bin)