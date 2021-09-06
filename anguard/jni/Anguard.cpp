//
// Created by n0ise on 9/5/2021.
//
#include <jni.h>
#include <chrono>
#include "aes.hpp"
#include "base64.h"
#include <android/log.h>
#include <random>
#include <algorithm>

//#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,    "TAG", __VA_ARGS__)

uint8_t key[] = {76, 103, 105, 76, 84, 117, 67, 82, 117, 119, 80, 89, 90, 107, 121, 90};

std::string jString2String(JNIEnv *env, jstring jStr) {
    if (!jStr)
        return "";
    const auto stringClass = env->GetObjectClass(jStr);
    const auto getBytes = env->GetMethodID(stringClass, "getBytes", "(Ljava/lang/String;)[B");
    const auto stringJbytes = (jbyteArray) env->CallObjectMethod(jStr, getBytes,
                                                                 env->NewStringUTF("UTF-8"));
    auto length = (size_t) env->GetArrayLength(stringJbytes);
    jbyte *pBytes = env->GetByteArrayElements(stringJbytes, nullptr);
    std::string ret = std::string((char *) pBytes, length);
    env->ReleaseByteArrayElements(stringJbytes, pBytes, JNI_ABORT);
    env->DeleteLocalRef(stringJbytes);
    env->DeleteLocalRef(stringClass);
    return ret;
}

jint hashCode;


extern "C" void JNICALL
Java_com_anguard_Anguard_initialize(JNIEnv *env, __unused jclass clazz, jobject context) {
    // context
    jclass native_context = env->GetObjectClass(context);
    // context.getPackageManager()
    jmethodID methodID_func = env->GetMethodID(native_context, "getPackageManager",
                                               "()Landroid/content/pm/PackageManager;");
    jobject package_manager = env->CallObjectMethod(context, methodID_func);
    jclass pm_clazz = env->GetObjectClass(package_manager);
    //packageManager.getPackageInfo()
    jmethodID methodId_pm = env->GetMethodID(pm_clazz, "getPackageInfo",
                                             "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    //context.getPackageName()
    jmethodID methodID_packagename = env->GetMethodID(native_context, "getPackageName",
                                                      "()Ljava/lang/String;");
    auto name_str = env->CallObjectMethod(context, methodID_packagename);
    jobject package_info = env->CallObjectMethod(package_manager, methodId_pm, name_str, 64);
    jclass pi_clazz = env->GetObjectClass(package_info);
    //packageInfo.signatures
    jfieldID fieldID_signatures = env->GetFieldID(pi_clazz, "signatures",
                                                  "[Landroid/content/pm/Signature;");
    jobject signatur = env->GetObjectField(package_info, fieldID_signatures);
    auto signatures = reinterpret_cast<jobjectArray>(signatur);
    //signatures[0]
    jobject signature = env->GetObjectArrayElement(signatures, 0);
    jclass s_clazz = env->GetObjectClass(signature);
    //signatures[0].toCharString()
    jmethodID methodId_ts = env->GetMethodID(s_clazz, "toCharsString", "()Ljava/lang/String;");
    jobject ts = env->CallObjectMethod(signature, methodId_ts);
    jclass ts_clazz = env->GetObjectClass(ts);
    //signatures[0].toCharString().hashCode()
    jmethodID hashCode_id = env->GetMethodID(ts_clazz, "hashCode", "()I");
    hashCode = env->CallIntMethod(ts, hashCode_id);
}

struct AES_ctx ctx;

extern "C" JNIEXPORT jstring
JNICALL Java_com_anguard_Anguard_getToken(JNIEnv *env, __unused jclass clazz,
                                          __unused jstring str) {
    std::string plain = std::to_string(hashCode) + "-" + std::to_string(std::time(nullptr)) +
                        jString2String(env, str);
    // LOGE("plain: %s", plain.c_str());
    // LOGE("key: %s",base64_encode(reinterpret_cast<const unsigned char *>(key), sizeof(key)).c_str());
    //generate random iv
    std::random_device random_device;
    std::default_random_engine rndEngine(random_device());
    std::uniform_int_distribution<int> intDistro(0, 255);
    auto *iv = new uint8_t[16];
    for (int i = 0; i < 16; ++i) {
        iv[i] = intDistro(rndEngine);
    }
    AES_init_ctx_iv(&ctx, key, iv);
    //LOGE("Iv: %s", base64_encode(reinterpret_cast<const unsigned char *>(ctx.Iv), 16).c_str());
    //create encrypted data buffer
    int encrypted_len = plain.length();
    auto *encrypted = new uint8_t[encrypted_len];
    for (int i = 0; i < encrypted_len; ++i) {
        encrypted[i] = plain[i];
    }
    //create output buffer
    int out_len = encrypted_len + 16;
    auto *out = new uint8_t[out_len];
    for (int i = 0; i < 16; ++i) {
        out[i] = iv[i];
    }
    AES_CTR_xcrypt_buffer(&ctx, encrypted, 64);
    // LOGE("encrypted: %s",base64_encode(reinterpret_cast<const unsigned char *>(encrypted), encrypted_len).c_str());
    //append encrypted data to output buffer
    for (int i = 0; i < encrypted_len; ++i) {
        out[i + 16] = encrypted[i];
    }
    std::string result = base64_encode(reinterpret_cast<const unsigned char *>(out), out_len);
    // LOGE("out %s", result.c_str());
    return (env)->NewStringUTF(result.c_str());
}
