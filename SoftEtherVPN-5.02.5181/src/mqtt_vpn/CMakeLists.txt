   # mqtt_vpn/CMakeLists.txt

   set(COMPONENT_NAME "MQTT VPN")
   set(COMPONENT_INTERNAL_NAME "mqtt_vpn")

   # 将 mqtt_vpn 改为静态库
   add_library(mqtt_vpn STATIC mqtt_vpn.c)

   set_target_properties(mqtt_vpn
     PROPERTIES
     ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
     LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
     RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
   )

   if(WIN32)
     set_target_properties(mqtt_vpn
       PROPERTIES
       PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
     )

     get_filename_component(COMPONENT_FILE_NAME mqtt_vpn NAME)
     set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

     configure_file("${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")

     target_sources(mqtt_vpn PRIVATE
       "ver.rc"
       "${TOP_DIRECTORY}/src/BuildFiles/Manifests/common.manifest"
     )
   endif()

   # 链接 cedar 库
   target_link_libraries(mqtt_vpn PRIVATE cedar)

   # 添加 OpenSSL 支持
   find_package(OpenSSL REQUIRED)
   target_link_libraries(mqtt_vpn PRIVATE OpenSSL::SSL OpenSSL::Crypto)

   # 添加 Windows 特定库
   if(WIN32)
     target_link_libraries(mqtt_vpn PRIVATE ws2_32 iphlpapi)
   endif()

   # 手动设置 Paho MQTT 库和头文件路径
   set(PAHO_MQTT3A_LIB "C:/Users/Administrator/source/repos/SoftEtherVPN-5.02.5181/vcpkg/installed/x64-windows/lib/paho-mqtt3a.lib")
   set(PAHO_MQTT3C_LIB "C:/Users/Administrator/source/repos/SoftEtherVPN-5.02.5181/vcpkg/installed/x64-windows/lib/paho-mqtt3c.lib")
   set(PAHO_MQTT_INCLUDE_DIR "C:/Users/Administrator/source/repos/SoftEtherVPN-5.02.5181/vcpkg/installed/x64-windows/include")

   # 检查库和头文件是否找到
   if(NOT EXISTS ${PAHO_MQTT3A_LIB})
     message(FATAL_ERROR "Could not find paho-mqtt3a library at ${PAHO_MQTT3A_LIB}")
   endif()

   if(NOT EXISTS ${PAHO_MQTT3C_LIB})
     message(FATAL_ERROR "Could not find paho-mqtt3c library at ${PAHO_MQTT3C_LIB}")
   endif()

   if(NOT EXISTS ${PAHO_MQTT_INCLUDE_DIR}/MQTTClient.h)
     message(FATAL_ERROR "Could not find Paho MQTT include directory at ${PAHO_MQTT_INCLUDE_DIR}")
   endif()

   # 链接库
   target_link_libraries(mqtt_vpn PRIVATE ${PAHO_MQTT3A_LIB} ${PAHO_MQTT3C_LIB})

   # 包含头文件目录
   target_include_directories(mqtt_vpn PRIVATE ${PAHO_MQTT_INCLUDE_DIR})

   # 手动设置 libsodium 库和头文件路径
   set(SODIUM_LIB "C:/Users/Administrator/source/repos/SoftEtherVPN-5.02.5181/vcpkg/installed/x64-windows/lib/libsodium.lib")
   set(SODIUM_INCLUDE_DIR "C:/Users/Administrator/source/repos/SoftEtherVPN-5.02.5181/vcpkg/installed/x64-windows/include")

   # 检查库和头文件是否找到
   if(NOT EXISTS ${SODIUM_LIB})
     message(FATAL_ERROR "Could not find libsodium library at ${SODIUM_LIB}")
   endif()

   if(NOT EXISTS ${SODIUM_INCLUDE_DIR}/sodium.h)
     message(FATAL_ERROR "Could not find libsodium include directory at ${SODIUM_INCLUDE_DIR}")
   endif()

   # 链接库
   target_link_libraries(mqtt_vpn PRIVATE ${SODIUM_LIB})

   # 包含头文件目录
   target_include_directories(mqtt_vpn PRIVATE ${SODIUM_INCLUDE_DIR})

   # 设置包含目录
   target_include_directories(mqtt_vpn PRIVATE 
       ${CMAKE_CURRENT_SOURCE_DIR}/..
       ${CMAKE_CURRENT_SOURCE_DIR}/../Mayaqua
       ${CMAKE_CURRENT_SOURCE_DIR}/../Cedar
   )

   # 添加编译定义
   target_compile_definitions(mqtt_vpn PRIVATE 
       WIN32
       _WINDOWS
       _CRT_SECURE_NO_WARNINGS
   )

   # 设置 C 标准
   set_target_properties(mqtt_vpn PROPERTIES
       C_STANDARD 99
       C_STANDARD_REQUIRED ON
   )
