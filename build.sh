#!/bin/bash
set -e

cargo build --lib --target x86_64-linux-android --target i686-linux-android --target armv7-linux-androideabi --target aarch64-linux-android
cargo run --bin uniffi-bindgen generate --library target/aarch64-linux-android/debug/librustpush.so --language kotlin --out-dir out

mkdir -p jniLibs/arm64-v8a/ && 
    cp target/aarch64-linux-android/debug/librustpush.so jniLibs/arm64-v8a/ &&
    mkdir -p jniLibs/armeabi-v7a/ &&
    cp target/armv7-linux-androideabi/debug/librustpush.so jniLibs/armeabi-v7a/ &&
    mkdir -p jniLibs/x86/ &&
    cp target/i686-linux-android/debug/librustpush.so jniLibs/x86/ &&
    mkdir -p jniLibs/x86_64/ &&
    cp target/x86_64-linux-android/debug/librustpush.so jniLibs/x86_64/

rm -rf /aosp/android_messages/app/src/main/jniLibs
cp -R jniLibs /aosp/android_messages/app/src/main

rm -rf /aosp/android_messages/app/src/main/java/uniffi
cp -R out/uniffi /aosp/android_messages/app/src/main/java/

echo "built"