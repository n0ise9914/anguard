cmake_minimum_required(VERSION 3.10.2)

add_library(anguard SHARED
        Anguard.cpp
        aes.c
        aes.h
        base64.cpp
        base64.h
        )

target_link_libraries(anguard
        android
        log)