  find_package(OpenSSL 3.0 REQUIRED)
  set(SOURCES
  algorithm/asn1.c
    algorithm/Pailliersrc.c
   # algorithm/store.c
    paillierprov.c
    #algorithm/encoder.c
    #algorithm/decoder.c
    
)
  add_library(Paillier SHARED ${SOURCES})
  set_target_properties(Paillier PROPERTIES
  POSITION_INDEPENDENT_CODE ON PREFIX "" 
  OUTPUT_NAME "Paillier")
  add_subdirectory(algorithm)
  #target_link_libraries(Elgamal elgamal_algorithm ${OPENSSL_CRYPTO_LIBRARIES})
  target_include_directories(Paillier PRIVATE ${OPENSSL_INCLUDE_DIR})
  target_include_directories(Paillier PRIVATE ${CMAKE_SOURCE_DIR}/algorithm)
  set_target_properties(Paillier PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "/usr/lib/x86_64-linux-gnu/ossl-modules"
    RUNTIME_OUTPUT_DIRECTORY "/usr/lib/x86_64-linux-gnu/ossl-modules"
)
  
  