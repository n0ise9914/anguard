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
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,    "TAG", __VA_ARGS__)

static uint8_t key[] = {76, 103, 105, 76, 84, 117, 67, 82, 117, 119, 80, 89, 90, 107, 121, 90};
static std::string signature_sha1;
const char hexcode[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E',
                        'F'};
struct AES_ctx ctx;
static std::random_device random_device;
static std::default_random_engine rndEngine(random_device());
static std::uniform_int_distribution<int> intDistro(0, 255);

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


std::string convertToString(char *a, int size) {
    int i;
    std::string s = "";
    for (i = 0; i < size; i++) {
        s = s + a[i];
    }
    return s;
}

std::basic_string<char, std::char_traits<char>, std::allocator<char>>
getSignature(JNIEnv *env, jobject context_object) {
    // Context object
    jclass context_class = env->GetObjectClass(context_object);

    // Reflection to obtain PackageManager
    // context.getPackageManager()
    jmethodID methodId = env->GetMethodID(context_class, "getPackageManager",
                                          "()Landroid/content/pm/PackageManager;");
    jobject package_manager = env->CallObjectMethod(context_object, methodId);
    if (package_manager == NULL) {
        // LOGD("package_manager is NULL!!!");
        return NULL;
    }

    // Reflect to get the package name
    // context.getPackageName()
    methodId = env->GetMethodID(context_class, "getPackageName", "()Ljava/lang/String;");
    jstring package_name = (jstring) env->CallObjectMethod(context_object, methodId);
    if (package_name == NULL) {
        // LOGD("package_name is NULL!!!");
        return NULL;
    }
    env->DeleteLocalRef(context_class);

    // Get PackageInfo object
    // packageManager.getPackageInfo()
    jclass pack_manager_class = env->GetObjectClass(package_manager);
    methodId = env->GetMethodID(pack_manager_class, "getPackageInfo",
                                "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    env->DeleteLocalRef(pack_manager_class);
    jobject package_info = env->CallObjectMethod(package_manager, methodId, package_name, 0x40);
    if (package_info == NULL) {
        // LOGD("getPackageInfo() is NULL!!!");
        return NULL;
    }
    env->DeleteLocalRef(package_manager);

    // Get signature information
    // packageInfo.signatures
    jclass package_info_class = env->GetObjectClass(package_info);
    jfieldID fieldId = env->GetFieldID(package_info_class, "signatures",
                                       "[Landroid/content/pm/Signature;");
    env->DeleteLocalRef(package_info_class);
    jobjectArray signature_object_array = (jobjectArray) env->GetObjectField(package_info, fieldId);
    if (signature_object_array == NULL) {
        // LOGD("signature is NULL!!!");
        return NULL;
    }
    jobject signature_object = env->GetObjectArrayElement(signature_object_array, 0);
    env->DeleteLocalRef(package_info);

    //The signature information is converted into sha1 value
    jclass signature_class = env->GetObjectClass(signature_object);
    methodId = env->GetMethodID(signature_class, "toByteArray", "()[B");
    env->DeleteLocalRef(signature_class);
    jbyteArray signature_byte = (jbyteArray) env->CallObjectMethod(signature_object, methodId);
    jclass byte_array_input_class = env->FindClass("java/io/ByteArrayInputStream");
    methodId = env->GetMethodID(byte_array_input_class, "<init>", "([B)V");
    jobject byte_array_input = env->NewObject(byte_array_input_class, methodId, signature_byte);
    jclass certificate_factory_class = env->FindClass("java/security/cert/CertificateFactory");
    methodId = env->GetStaticMethodID(certificate_factory_class, "getInstance",
                                      "(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
    jstring x_509_jstring = env->NewStringUTF("X.509");
    jobject cert_factory = env->CallStaticObjectMethod(certificate_factory_class, methodId,
                                                       x_509_jstring);
    methodId = env->GetMethodID(certificate_factory_class, "generateCertificate",
                                ("(Ljava/io/InputStream;)Ljava/security/cert/Certificate;"));
    jobject x509_cert = env->CallObjectMethod(cert_factory, methodId, byte_array_input);
    env->DeleteLocalRef(certificate_factory_class);
    jclass x509_cert_class = env->GetObjectClass(x509_cert);
    methodId = env->GetMethodID(x509_cert_class, "getEncoded", "()[B");
    jbyteArray cert_byte = (jbyteArray) env->CallObjectMethod(x509_cert, methodId);
    env->DeleteLocalRef(x509_cert_class);
    jclass message_digest_class = env->FindClass("java/security/MessageDigest");
    methodId = env->GetStaticMethodID(message_digest_class, "getInstance",
                                      "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring sha1_jstring = env->NewStringUTF("SHA1");
    jobject sha1_digest = env->CallStaticObjectMethod(message_digest_class, methodId, sha1_jstring);
    methodId = env->GetMethodID(message_digest_class, "digest", "([B)[B");
    jbyteArray sha1_byte = (jbyteArray) env->CallObjectMethod(sha1_digest, methodId, cert_byte);
    env->DeleteLocalRef(message_digest_class);

    // Convert to char
    jsize array_size = env->GetArrayLength(sha1_byte);
    jbyte *sha1 = env->GetByteArrayElements(sha1_byte, NULL);
    char *hex_sha = new char[array_size * 2 + 1];
    for (int i = 0; i < array_size; ++i) {
        hex_sha[2 * i] = hexcode[((unsigned char) sha1[i]) / 16];
        hex_sha[2 * i + 1] = hexcode[((unsigned char) sha1[i]) % 16];
    }
    hex_sha[array_size * 2] = '\0';
    signature_sha1 = convertToString(hex_sha, array_size * 2);
    delete[] sha1;
    delete[] hex_sha;
    return signature_sha1;
}

extern "C" void JNICALL
Java_com_anguard_Anguard_initialize(JNIEnv *env, __unused jclass clazz, jobject context_object) {
    signature_sha1 = getSignature(env, context_object);
}

extern "C" JNIEXPORT jstring
JNICALL Java_com_anguard_Anguard_getToken(JNIEnv *env, __unused jclass clazz,
                                          __unused jstring str) {

    std::string plain = signature_sha1 + "-" + std::to_string(std::time(nullptr)) +
                        jString2String(env, str);
    // LOGE("plain: %s", plain.c_str());
    // LOGE("key: %s",base64_encode(reinterpret_cast<const unsigned char *>(key), sizeof(key)).c_str());
    //generate random iv
    uint8_t *iv = new uint8_t[16];
    for (int i = 0; i < 16; ++i) {
        iv[i] = intDistro(rndEngine);
    }
    AES_init_ctx_iv(&ctx, key, iv);
    //LOGE("Iv: %s", base64_encode(reinterpret_cast<const unsigned char *>(ctx.Iv), 16).c_str());
    //create encrypted data buffer
    int encrypted_len = plain.length();
    uint8_t *encrypted = new uint8_t[encrypted_len];
    for (int i = 0; i < encrypted_len; ++i) {
        encrypted[i] = plain[i];
    }
    //create output buffer
    int out_len = encrypted_len + 16;
    uint8_t *out = new uint8_t[out_len];
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
    delete[] iv;
    delete[] encrypted;
    delete[] out;
    return (env)->NewStringUTF(result.c_str());
}
