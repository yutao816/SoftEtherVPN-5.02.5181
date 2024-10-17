# mqtt_vpn/CMakeLists.txt

set(COMPONENT_NAME "MQTT VPN")
set(COMPONENT_INTERNAL_NAME "mqtt_vpn")

add_executable(mqtt_vpn mqtt_vpn.c)

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

target_link_libraries(mqtt_vpn cedar)

# 添加 OpenSSL 支持
find_package(OpenSSL REQUIRED)
target_link_libraries(mqtt_vpn PRIVATE ${OPENSSL_LIBRARIES})
target_include_directories(mqtt_vpn PRIVATE ${OPENSSL_INCLUDE_DIR})

# 添加 Windows 特定库
if(WIN32)
  target_link_libraries(mqtt_vpn PRIVATE ws2_32 iphlpapi)
endif()

# 如果使用 Paho MQTT 客户端库，添加以下内容：
# find_package(PahoMQTTC REQUIRED)
# target_link_libraries(mqtt_vpn PRIVATE PahoMQTTC::PahoMQTTC)

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