#include "endpoint.h"
#include "reauth.h"

#include <jni.h>
#include <stdint.h>
#include <string.h>

int rb_install(const rb_config *cfg);
int rb_reauth_set_initial_uuid_cstr(const char *uuid);
int rb_reauth_complete_cstr(uint64_t epoch, const char *uuid);

static JavaVM *g_vm;
static jclass g_reset_cls;
static jmethodID g_reset_mid;

static void clear_exc(JNIEnv *env) {
    if (env && (*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
    }
}

static int read_valid_uuid(JNIEnv *env, jstring jstr, char out[RB_UUID_MAX + 1]) {
    jsize nbytes;
    const char *utf;
    int ok;
    if (!env || !jstr || !out) {
        return 0;
    }
    nbytes = (*env)->GetStringUTFLength(env, jstr);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        return 0;
    }
    if (nbytes <= 0 || nbytes > RB_UUID_MAX) {
        return 0;
    }
    utf = (*env)->GetStringUTFChars(env, jstr, NULL);
    if (!utf) {
        clear_exc(env);
        return 0;
    }
    ok = (strlen(utf) == (size_t)nbytes && rb_valid_uuid(utf));
    if (ok) {
        memcpy(out, utf, (size_t)nbytes + 1);
    }
    (*env)->ReleaseStringUTFChars(env, jstr, utf);
    return ok;
}

void rb_jni_notify_reset(uint64_t epoch, int reason) {
    JavaVM *vm = __atomic_load_n(&g_vm, __ATOMIC_ACQUIRE);
    jclass cls = __atomic_load_n(&g_reset_cls, __ATOMIC_ACQUIRE);
    jmethodID mid = __atomic_load_n(&g_reset_mid, __ATOMIC_ACQUIRE);
    JNIEnv *env = NULL;
    int attached = 0;
    jint rc;

    if (!vm || !cls || !mid) {
        return;
    }
    rc = (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);
    if (rc == JNI_EDETACHED) {
        if ((*vm)->AttachCurrentThread(vm, &env, NULL) != JNI_OK || !env) {
            return;
        }
        attached = 1;
    } else if (rc != JNI_OK || !env) {
        return;
    }
    (*env)->CallStaticVoidMethod(env, cls, mid, (jlong)epoch, (jint)reason);
    clear_exc(env);
    if (attached) {
        (*vm)->DetachCurrentThread(vm);
    }
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    __atomic_store_n(&g_vm, vm, __ATOMIC_RELEASE);
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
    jmethodID mid;
    jclass gref = NULL;
    int had_cls;
    jboolean ok = JNI_FALSE;
    int i;

    if (!env || !clazz || !host || !ports) {
        return JNI_FALSE;
    }
    nports = (*env)->GetArrayLength(env, ports);
    if ((*env)->ExceptionCheck(env) || nports != RB_PORT_N) {
        clear_exc(env);
        return JNI_FALSE;
    }
    utf = (*env)->GetStringUTFChars(env, host, NULL);
    if (!utf) {
        clear_exc(env);
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
    if (!rb_validate(utf, mapped, &cfg)) {
        goto out;
    }
    mid = (*env)->GetStaticMethodID(env, clazz, "onResetRequested", "(JI)V");
    if (!mid || (*env)->ExceptionCheck(env)) {
        clear_exc(env);
        goto out;
    }
    had_cls = (__atomic_load_n(&g_reset_cls, __ATOMIC_ACQUIRE) != NULL);
    if (!had_cls) {
        gref = (jclass)(*env)->NewGlobalRef(env, clazz);
        if (!gref || (*env)->ExceptionCheck(env)) {
            clear_exc(env);
            if (gref) {
                (*env)->DeleteGlobalRef(env, gref);
            }
            goto out;
        }
        __atomic_store_n(&g_reset_mid, mid, __ATOMIC_RELEASE);
        __atomic_store_n(&g_reset_cls, gref, __ATOMIC_RELEASE);
    }
    if (rb_install(&cfg) != 0) {
        if (!had_cls) {
            __atomic_store_n(&g_reset_cls, NULL, __ATOMIC_RELEASE);
            __atomic_store_n(&g_reset_mid, NULL, __ATOMIC_RELEASE);
            (*env)->DeleteGlobalRef(env, gref);
        }
        goto out;
    }
    ok = JNI_TRUE;
out:
    (*env)->ReleaseStringUTFChars(env, host, utf);
    return ok;
}

JNIEXPORT jboolean JNICALL Java_dev_raspberry_Raspberry_nativeSetAuthUuid(JNIEnv *env, jclass clazz,
                                                                          jstring uuid) {
    char buf[RB_UUID_MAX + 1];
    (void)clazz;
    if (!read_valid_uuid(env, uuid, buf)) {
        return JNI_FALSE;
    }
    return rb_reauth_set_initial_uuid_cstr(buf) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_dev_raspberry_Raspberry_nativeOnReauthComplete(JNIEnv *env, jclass clazz,
                                                                               jlong epoch, jstring uuid) {
    char buf[RB_UUID_MAX + 1];
    (void)clazz;
    if (epoch <= 0 || !read_valid_uuid(env, uuid, buf)) {
        return JNI_FALSE;
    }
    return rb_reauth_complete_cstr((uint64_t)epoch, buf) ? JNI_TRUE : JNI_FALSE;
}
