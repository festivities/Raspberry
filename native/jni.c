#include "endpoint.h"

#include <jni.h>
#include <string.h>

int rb_install(const rb_config *cfg);

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    return JNI_VERSION_1_6;
}

JNIEXPORT jboolean JNICALL Java_dev_raspberry_Raspberry_installNative(JNIEnv *env, jclass clazz,
                                                                      jstring host, jintArray ports) {
    const char *utf = NULL;
    jsize nbytes;
    jsize nports;
    jint tmp[RB_PORT_N];
    int mapped[RB_PORT_N];
    rb_config cfg;
    jboolean ok = JNI_FALSE;
    int i;
    (void)clazz;
    if (!env || !host || !ports) {
        return JNI_FALSE;
    }
    nports = (*env)->GetArrayLength(env, ports);
    if ((*env)->ExceptionCheck(env) || nports != RB_PORT_N) {
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
        }
        return JNI_FALSE;
    }
    utf = (*env)->GetStringUTFChars(env, host, NULL);
    if (!utf) {
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
        }
        return JNI_FALSE;
    }
    nbytes = (*env)->GetStringUTFLength(env, host);
    if (nbytes < 0 || (size_t)nbytes > RB_HOST_MAX || strlen(utf) != (size_t)nbytes) {
        goto out;
    }
    (*env)->GetIntArrayRegion(env, ports, 0, RB_PORT_N, tmp);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        goto out;
    }
    for (i = 0; i < RB_PORT_N; i++) {
        mapped[i] = (int)tmp[i];
    }
    if (!rb_validate(utf, mapped, &cfg) || rb_install(&cfg) != 0) {
        goto out;
    }
    ok = JNI_TRUE;
out:
    (*env)->ReleaseStringUTFChars(env, host, utf);
    return ok;
}
