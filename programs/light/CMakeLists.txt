add_executable(ecdh_aes ecdh_aes.c)
target_link_libraries(ecdh_aes mbedcrypto)

install(TARGETS ecdh_aes
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
