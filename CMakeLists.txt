cmake_minimum_required(VERSION 3.21 FATAL_ERROR)
project(
  Paillier-provider
  VERSION 1.0
  DESCRIPTION "An implementation of Paillier encryption scheme as provider for OpenSSL 3.0"
  LANGUAGES C)
  set(CMAKE_C_STANDARD 99)
  find_package(OpenSSL 3.0 REQUIRED)
  add_subdirectory(src)
  
  
