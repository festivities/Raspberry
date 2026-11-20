#import "RBRaspberryRuntime.h"

#import "RBASWebAuthenticationSessionDriver.h"
#import "RBAuthAttempt.h"
#import "RBAuthBrowserSession.h"
#import "RBAuthCallbackSanitizer.h"
#import "RBAuthExchangeClient.h"
#import "RBAuthFlowCoordinator.h"
#import "RBAuthGuestCredentialGate.h"
#import "RBAuthSignInSessionController.h"
#import "RBAuthStore.h"
#import "RBAuthUIKitLifecycleBinding.h"
#import "RBAuthUIKitOwnerConditions.h"
#import "RBAuthUIKitSignInOverlay.h"
#import "RBEndpoint.h"
#import "RBNoticeRouteClient.h"
#import "RBNoticeRouteErrorAdapter.h"
#import "RBWebURLRouter.h"

#include "RBSocketRouter.h"
#include "endpoint.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#import <UIKit/UIKit.h>
#import <dispatch/dispatch.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <objc/message.h>
#import <objc/runtime.h>

static const uintptr_t RBRaspberryRuntimeContinuationRVA = 0x12D8BE8u;
static const uintptr_t RBRaspberryRuntimeRequestMethodRVA = 0x12D7648u;
static const uintptr_t RBRaspberryRuntimeUserAgentRVA = 0x12D6368u;
static const uintptr_t RBRaspberryRuntimeLCErrorFactoryRVA = 0x12EBF00u;
static const uint64_t RBRaspberryRuntimePreferredImageBase = 0x100000000ULL;
static const uint64_t RBRaspberryRuntimeLCError404Type = 2u;
static const int64_t RBRaspberryRuntimeHTTP404Code = 404;
static const uint64_t RBRaspberryRuntimeLocalErrorType = 1u;
static const int64_t RBRaspberryRuntimeLocalErrorCode = 1;
static NSString *const RBRaspberryRuntimeLocalErrorDomain =
    @"org.raspberry.ios.runtime.local";

typedef struct {
    const struct mach_header_64 *header;
    const char *imagePath;
    uint64_t textVMAddress;
    uint64_t textVMSize;
    vm_prot_t textInitialProtection;
} RBRaspberryRuntimeMainImage;

static RBRaspberryRuntimeMainImage RBRaspberryRuntimeMainImageInfo;
static Class RBRaspberryRuntimeNoticeCenterClass;
static IMP RBRaspberryRuntimeUserAgentExpectedIMP;
static RBAuthSignInSessionController * __strong RBRaspberryRuntimeSessionController;
static RBAuthUIKitSignInOverlay * __strong RBRaspberryRuntimeSignInOverlay;
static id __strong RBRaspberryRuntimeDidBecomeActiveObserver;
static id __strong RBRaspberryRuntimeKeyWindowObserver;
static NSTimer * __strong RBRaspberryRuntimeOverlayPollTimer;
static NSUInteger RBRaspberryRuntimeOverlayPollAttempts = 0;

static const NSUInteger RBRaspberryRuntimeUserAgentLimit = 512u;
static NSString *const RBRaspberryRuntimeSourcePrefix =
    @"https://lan3rd.line.me/v1/lineplay/ios";
static NSString *const RBRaspberryRuntimeSourcePath = @"/v1/lineplay/ios";

static _Atomic(uint32_t) RBRaspberryRuntimeReadiness = 0;
static _Atomic(uint32_t) RBRaspberryRuntimeRouterInitialized = 0;
static _Atomic(bool) RBRaspberryRuntimeHasEndpoint = false;
static _Atomic(bool) RBRaspberryRuntimeAttemptedOnce = false;
static RBSocketRouter RBRaspberryRuntimeSocketRouter;
static id __strong RBRaspberryRuntimeHTTP404Error;
static id __strong RBRaspberryRuntimeLocalError;
static RBEndpoint * __strong RBRaspberryRuntimeEndpoint;
static RBAuthGuestCredentialGate * __strong RBRaspberryRuntimeGate;
static id __unsafe_unretained RBRaspberryRuntimeExpectedReceiver;
static SEL RBRaspberryRuntimeExpectedSelector;
static SEL RBRaspberryRuntimeUserAgentSelector;
static uintptr_t RBRaspberryRuntimeExpectedContinuation;

typedef id (*RBRaspberryRuntimeErrorFactorySend)(
    id receiver, SEL selector, uint64_t type, NSString *domain, int64_t code);
typedef id (*RBRaspberryRuntimeUserAgentSend)(id receiver, SEL selector);

static id RBRaspberryRuntimeSendErrorFactory(
    id receiver, SEL selector, uint64_t type, NSString *domain, int64_t code) {
    RBRaspberryRuntimeErrorFactorySend send =
        (RBRaspberryRuntimeErrorFactorySend)(void *)objc_msgSend;
    return send(receiver, selector, type, domain, code);
}

static id RBRaspberryRuntimeSendUserAgent(id receiver, SEL selector) {
    RBRaspberryRuntimeUserAgentSend send =
        (RBRaspberryRuntimeUserAgentSend)(void *)objc_msgSend;
    return send(receiver, selector);
}

static NSString * _Nullable RBRaspberryRuntimeValidatedUserAgent(
    id _Nullable candidate) {
    if (candidate == nil || ![candidate isKindOfClass:[NSString class]]) {
        return nil;
    }
    NSString *string = (NSString *)candidate;
    if (string.length == 0 || string.length > RBRaspberryRuntimeUserAgentLimit) {
        return nil;
    }
    for (NSUInteger index = 0; index < string.length; index++) {
        unichar character = [string characterAtIndex:index];
        if (character < 0x20 || character > 0x7E) {
            return nil;
        }
    }
    return [string copy];
}

static RBEndpoint * _Nullable RBRaspberryRuntimeLoadEndpointFromFileURL(
    NSURL * _Nullable endpointFileURL) {
    if (endpointFileURL == nil) {
        return nil;
    }
    @try {
        NSError *error = nil;
        RBEndpoint *endpoint =
            [RBEndpoint endpointFromFileURL:endpointFileURL error:&error];
        (void)error;
        return endpoint;
    } @catch (id exception) {
        (void)exception;
        return nil;
    }
}

static NSURL * _Nullable RBRaspberryRuntimePrepareSecureDirectoryURL(
    NSURL * _Nullable rawURL) {
    if (rawURL == nil || !rawURL.isFileURL || rawURL.path.length == 0) {
        return nil;
    }
    const char *raw = NULL;
    @try {
        raw = rawURL.fileSystemRepresentation;
    } @catch (id exception) {
        (void)exception;
        raw = NULL;
    }
    if (raw == NULL || raw[0] != '/') {
        return nil;
    }
    size_t len = strlen(raw);
    if (len == 0 || len >= PATH_MAX) {
        return nil;
    }
    // Strip trailing slashes so POSIX O_NOFOLLOW never resolves a symlink via "sym/.".
    while (len > 1 && raw[len - 1] == '/') {
        len--;
    }
    char cleanPath[PATH_MAX];
    memcpy(cleanPath, raw, len);
    cleanPath[len] = '\0';

    BOOL created = NO;
    int fd = open(cleanPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) {
        if (mkdir(cleanPath, 0700) == 0) {
            created = YES;
        } else if (errno != EEXIST) {
            return nil;
        }
        fd = open(cleanPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
    if (fd < 0) {
        return nil;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 ||
        !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        (void)close(fd);
        return nil;
    }
    if (created && (st.st_mode & 0777) != 0700) {
        if (fchmod(fd, 0700) != 0) {
            (void)close(fd);
            return nil;
        }
    }
    (void)close(fd);

    NSString *cleanString = [[NSString alloc] initWithBytes:cleanPath
                                                     length:len
                                                   encoding:NSUTF8StringEncoding];
    if (cleanString == nil) {
        return nil;
    }
    return [NSURL fileURLWithPath:cleanString isDirectory:YES];
}

static RBAuthGuestCredentialGate * _Nullable RBRaspberryRuntimeInitializeGate(
    RBEndpoint * _Nullable endpoint,
    NSURL * _Nullable rawAppSupportURL,
    NSURL * _Nullable rawCachesURL) {
    (void)[RBAuthCallbackSanitizer class];
    if (endpoint == nil) {
        return nil;
    }
    NSURL *appSupportURL = RBRaspberryRuntimePrepareSecureDirectoryURL(rawAppSupportURL);
    NSURL *cachesURL = RBRaspberryRuntimePrepareSecureDirectoryURL(rawCachesURL);
    if (appSupportURL == nil || cachesURL == nil) {
        return nil;
    }
    RBAuthStore *store = [[RBAuthStore alloc] initWithBaseDirectoryURL:appSupportURL
                                                    cachesDirectoryURL:cachesURL];
    if (store == nil) {
        return nil;
    }
    RBAuthGuestCredentialGate *gate =
        [[RBAuthGuestCredentialGate alloc] initWithEndpoint:endpoint
                                                  authStore:store];
    if (gate == nil) {
        return nil;
    }
    (void)[gate reloadFromStoreError:NULL];
    return gate;
}

static bool RBRaspberryRuntimeIsMarkerIPv4(
    const struct sockaddr *addr, socklen_t addrlen) {
    if (addr == NULL || addrlen < (socklen_t)sizeof(struct sockaddr_in) ||
        addr->sa_family != AF_INET) {
        return false;
    }
    struct sockaddr_in sin;
    memcpy(&sin, addr, sizeof(sin));
    return memcmp(&sin.sin_addr, rb_marker(), 4) == 0;
}

static const rb_socket_ops * _Nullable RBRaspberryRuntimeFallbackOps(void) {
    static const rb_socket_ops kProductionOps = {
        .real_getaddrinfo = &getaddrinfo,
        .real_freeaddrinfo = &freeaddrinfo,
        .real_gethostbyname = &gethostbyname,
        .real_connect = &connect,
        .now_monotonic_sec = NULL,
    };
    return &kProductionOps;
}

static BOOL RBRaspberryRuntimeHexDigit(unichar character) {
    return (character >= '0' && character <= '9') ||
           (character >= 'a' && character <= 'f') ||
           (character >= 'A' && character <= 'F');
}

static BOOL RBRaspberryRuntimeQueryCharacter(unichar character) {
    if ((character >= 'a' && character <= 'z') ||
        (character >= 'A' && character <= 'Z') ||
        (character >= '0' && character <= '9')) {
        return YES;
    }
    switch (character) {
        case '-': case '.': case '_': case '~':
        case '!': case '$': case '&': case '\'': case '(':
        case ')': case '*': case '+': case ',': case ';':
        case '=': case ':': case '@': case '/': case '?':
            return YES;
        default:
            return NO;
    }
}

static BOOL RBRaspberryRuntimeValidQuery(NSString *query) {
    for (NSUInteger index = 0; index < query.length; index++) {
        unichar character = [query characterAtIndex:index];
        if (character == '%') {
            if (index + 2 >= query.length ||
                !RBRaspberryRuntimeHexDigit([query characterAtIndex:index + 1]) ||
                !RBRaspberryRuntimeHexDigit([query characterAtIndex:index + 2])) {
                return NO;
            }
            index += 2;
        } else if (!RBRaspberryRuntimeQueryCharacter(character)) {
            return NO;
        }
    }
    return YES;
}

static BOOL RBRaspberryRuntimeCanonicalSourceString(NSString * _Nullable URLString) {
    if (URLString == nil || URLString.length == 0 ||
        URLString.length > 8u * 1024u ||
        [URLString rangeOfCharacterFromSet:
            [NSCharacterSet controlCharacterSet]].location != NSNotFound ||
        [URLString rangeOfString:@"#"].location != NSNotFound ||
        ![URLString hasPrefix:RBRaspberryRuntimeSourcePrefix]) {
        return NO;
    }

    NSString *tail = [URLString substringFromIndex:
        RBRaspberryRuntimeSourcePrefix.length];
    NSString *rawQuery = nil;
    if (tail.length != 0) {
        if (![tail hasPrefix:@"?"]) {
            return NO;
        }
        rawQuery = [tail substringFromIndex:1];
        if (!RBRaspberryRuntimeValidQuery(rawQuery)) {
            return NO;
        }
    }

    NSURLComponents *components =
        [NSURLComponents componentsWithString:URLString];
    if (components == nil ||
        ![components.scheme isEqualToString:@"https"] ||
        ![components.host isEqualToString:@"lan3rd.line.me"] ||
        components.port != nil ||
        components.user != nil ||
        components.password != nil ||
        ![components.percentEncodedPath isEqualToString:RBRaspberryRuntimeSourcePath] ||
        components.fragment != nil ||
        ((rawQuery == nil && components.percentEncodedQuery != nil) ||
         (rawQuery != nil &&
          ![components.percentEncodedQuery isEqualToString:rawQuery])) ||
        components.URL == nil) {
        return NO;
    }
    return YES;
}

static BOOL RBRaspberryRuntimeArgumentsMatch(
    id __unsafe_unretained receiver,
    SEL selector,
    id __unsafe_unretained URL,
    id __unsafe_unretained name,
    uintptr_t callerLR,
    NSString * _Nullable * _Nonnull sourceURLStringOut) {
    *sourceURLStringOut = nil;
    if (callerLR != RBRaspberryRuntimeExpectedContinuation ||
        receiver != RBRaspberryRuntimeExpectedReceiver ||
        selector == NULL ||
        !sel_isEqual(selector, RBRaspberryRuntimeExpectedSelector) ||
        NSThread.isMainThread ||
        ![URL isKindOfClass:[NSURL class]] ||
        ![name isKindOfClass:[NSString class]] ||
        ![(NSString *)name isEqualToString:@"Notice"]) {
        return NO;
    }

    NSString *sourceURLString = [(NSURL *)URL absoluteString];
    if (!RBRaspberryRuntimeCanonicalSourceString(sourceURLString)) {
        return NO;
    }
    *sourceURLStringOut = [sourceURLString copy];
    return YES;
}

static id RBRaspberryRuntimeFailClosed(void) {
    id localError = RBRaspberryRuntimeLocalError;
    if (localError == nil) {
        __builtin_trap();
    }
    return localError;
}

static BOOL RBRaspberryRuntimeReadTextSegment(
    const struct mach_header_64 *header,
    uint64_t *textVMAddress,
    uint64_t *textVMSize,
    vm_prot_t *textInitialProtection) {
    if (header == NULL || header->magic != MH_MAGIC_64 ||
        header->filetype != MH_EXECUTE || header->cputype != CPU_TYPE_ARM64 ||
        header->ncmds == 0 || header->ncmds > 4096 ||
        header->sizeofcmds == 0 || header->sizeofcmds > 1024u * 1024u) {
        return NO;
    }

    const uint8_t *cursor = (const uint8_t *)(header + 1);
    size_t remaining = header->sizeofcmds;
    BOOL foundText = NO;
    for (uint32_t index = 0; index < header->ncmds; index++) {
        if (remaining < sizeof(struct load_command)) {
            return NO;
        }
        const struct load_command *loadCommand =
            (const struct load_command *)cursor;
        if (loadCommand->cmdsize < sizeof(struct load_command) ||
            loadCommand->cmdsize > remaining ||
            (loadCommand->cmdsize & (sizeof(uint32_t) - 1u)) != 0) {
            return NO;
        }
        if (loadCommand->cmd == LC_SEGMENT_64) {
            if (loadCommand->cmdsize < sizeof(struct segment_command_64)) {
                return NO;
            }
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)loadCommand;
            if (strncmp(segment->segname, "__TEXT",
                        sizeof(segment->segname)) == 0) {
                if (foundText) {
                    return NO;
                }
                foundText = YES;
                *textVMAddress = segment->vmaddr;
                *textVMSize = segment->vmsize;
                *textInitialProtection = segment->initprot;
            }
        }
        cursor += loadCommand->cmdsize;
        remaining -= loadCommand->cmdsize;
    }
    return foundText && remaining == 0 &&
        *textVMAddress == RBRaspberryRuntimePreferredImageBase &&
        (*textInitialProtection & VM_PROT_EXECUTE) != 0;
}

static BOOL RBRaspberryRuntimeFindUniqueMainImage(
    RBRaspberryRuntimeMainImage *mainImage) {
    if (mainImage == NULL) {
        return NO;
    }
    uint32_t imageCount = _dyld_image_count();
    if (imageCount == 0 || imageCount > 4096) {
        return NO;
    }

    NSUInteger executableCount = 0;
    const struct mach_header_64 *candidateHeader = NULL;
    const char *candidatePath = NULL;
    for (uint32_t index = 0; index < imageCount; index++) {
        const struct mach_header *header = _dyld_get_image_header(index);
        if (header == NULL || header->magic != MH_MAGIC_64) {
            continue;
        }
        const struct mach_header_64 *header64 =
            (const struct mach_header_64 *)header;
        if (header64->filetype == MH_EXECUTE) {
            executableCount++;
            candidateHeader = header64;
            candidatePath = _dyld_get_image_name(index);
        }
    }
    if (executableCount != 1 || candidateHeader == NULL ||
        candidatePath == NULL) {
        return NO;
    }

    NSString *executablePath = NSBundle.mainBundle.executablePath;
    NSString *bundleIdentifier = NSBundle.mainBundle.bundleIdentifier;
    if (executablePath == nil || bundleIdentifier == nil ||
        ![bundleIdentifier isEqualToString:@"jp.naver.lineplay"] ||
        ![[executablePath lastPathComponent]
            isEqualToString:@"LINEPlay_Store"] ||
        strcmp(candidatePath, executablePath.fileSystemRepresentation) != 0) {
        return NO;
    }

    uint64_t textVMAddress = 0;
    uint64_t textVMSize = 0;
    vm_prot_t textInitialProtection = 0;
    if (!RBRaspberryRuntimeReadTextSegment(candidateHeader, &textVMAddress,
            &textVMSize, &textInitialProtection)) {
        return NO;
    }

    mainImage->header = candidateHeader;
    mainImage->imagePath = candidatePath;
    mainImage->textVMAddress = textVMAddress;
    mainImage->textVMSize = textVMSize;
    mainImage->textInitialProtection = textInitialProtection;
    return YES;
}

static BOOL RBRaspberryRuntimeRVAIsExecutable(
    const RBRaspberryRuntimeMainImage *mainImage,
    uintptr_t rva,
    size_t size) {
    if (mainImage == NULL ||
        (mainImage->textInitialProtection & VM_PROT_EXECUTE) == 0 ||
        mainImage->textVMAddress != RBRaspberryRuntimePreferredImageBase ||
        size == 0 || rva > UINTPTR_MAX - size) {
        return NO;
    }
    uint64_t textRVA = mainImage->textVMAddress -
        RBRaspberryRuntimePreferredImageBase;
    if (mainImage->textVMSize > UINT64_MAX - textRVA) {
        return NO;
    }
    return (uint64_t)rva >= textRVA &&
        (uint64_t)rva + size <= textRVA + mainImage->textVMSize;
}

static BOOL RBRaspberryRuntimeClassIsInMainImage(
    Class candidateClass,
    const RBRaspberryRuntimeMainImage *mainImage) {
    if (candidateClass == Nil || mainImage == NULL ||
        mainImage->imagePath == NULL) {
        return NO;
    }
    const char *classImage = class_getImageName(candidateClass);
    return classImage != NULL &&
        strcmp(classImage, mainImage->imagePath) == 0;
}

static BOOL RBRaspberryRuntimeMethodMatches(
    Class targetClass,
    SEL selector,
    const char *expectedEncoding,
    uintptr_t expectedRVA,
    const RBRaspberryRuntimeMainImage *mainImage,
    IMP *implementationOut) {
    if (targetClass == Nil || selector == NULL ||
        expectedEncoding == NULL || mainImage == NULL ||
        !RBRaspberryRuntimeClassIsInMainImage(targetClass, mainImage) ||
        !RBRaspberryRuntimeRVAIsExecutable(mainImage, expectedRVA, 1)) {
        return NO;
    }
    Method method = class_getClassMethod(targetClass, selector);
    if (method == NULL) {
        return NO;
    }
    uintptr_t imageBase = (uintptr_t)mainImage->header;
    if (imageBase > UINTPTR_MAX - expectedRVA) {
        return NO;
    }
    const char *encoding = method_getTypeEncoding(method);
    IMP implementation = method_getImplementation(method);
    uintptr_t expectedIMP = imageBase + expectedRVA;
    if (encoding == NULL || strcmp(encoding, expectedEncoding) != 0 ||
        implementation == NULL ||
        (uintptr_t)implementation != expectedIMP) {
        return NO;
    }
    if (implementationOut != NULL) {
        *implementationOut = implementation;
    }
    return YES;
}

static BOOL RBRaspberryRuntimeValidateError(
    id candidate,
    Class expectedClass,
    NSString *expectedDomain,
    int64_t expectedCode) {
    if (candidate == nil || expectedClass == Nil ||
        object_getClass(candidate) != expectedClass ||
        ![candidate isKindOfClass:[NSError class]]) {
        return NO;
    }
    NSError *error = (NSError *)candidate;
    return [error.domain isEqualToString:expectedDomain] &&
        error.code == (NSInteger)expectedCode &&
        error.userInfo.count == 0;
}

static BOOL RBRaspberryRuntimePrepareErrors(
    Class errorClass,
    SEL factorySelector,
    IMP expectedFactoryImplementation,
    const RBRaspberryRuntimeMainImage *mainImage) {
    if (errorClass == Nil || factorySelector == NULL ||
        expectedFactoryImplementation == NULL || mainImage == NULL) {
        return NO;
    }
    NSString *notFoundDomain =
        [NSHTTPURLResponse localizedStringForStatusCode:404];
    if (notFoundDomain.length == 0) {
        return NO;
    }

    // Typed objc_msgSend preserves normal +initialize; IMP is guarded before
    // and re-checked after each invocation.
    id notFound = RBRaspberryRuntimeSendErrorFactory(errorClass, factorySelector,
        RBRaspberryRuntimeLCError404Type, notFoundDomain,
        RBRaspberryRuntimeHTTP404Code);
    IMP currentFactoryImplementation = NULL;
    if (!RBRaspberryRuntimeMethodMatches(errorClass, factorySelector,
            "@40@0:8Q16@24q32", RBRaspberryRuntimeLCErrorFactoryRVA,
            mainImage, &currentFactoryImplementation) ||
        currentFactoryImplementation != expectedFactoryImplementation) {
        return NO;
    }
    if (!RBRaspberryRuntimeValidateError(notFound, errorClass,
            notFoundDomain, RBRaspberryRuntimeHTTP404Code)) {
        return NO;
    }

    if (!RBRaspberryRuntimeMethodMatches(errorClass, factorySelector,
            "@40@0:8Q16@24q32", RBRaspberryRuntimeLCErrorFactoryRVA,
            mainImage, &currentFactoryImplementation) ||
        currentFactoryImplementation != expectedFactoryImplementation) {
        return NO;
    }
    id local = RBRaspberryRuntimeSendErrorFactory(errorClass, factorySelector,
        RBRaspberryRuntimeLocalErrorType, RBRaspberryRuntimeLocalErrorDomain,
        RBRaspberryRuntimeLocalErrorCode);
    if (!RBRaspberryRuntimeMethodMatches(errorClass, factorySelector,
            "@40@0:8Q16@24q32", RBRaspberryRuntimeLCErrorFactoryRVA,
            mainImage, &currentFactoryImplementation) ||
        currentFactoryImplementation != expectedFactoryImplementation) {
        return NO;
    }
    if (!RBRaspberryRuntimeValidateError(local, errorClass,
            RBRaspberryRuntimeLocalErrorDomain,
            RBRaspberryRuntimeLocalErrorCode) ||
        local == notFound) {
        return NO;
    }

    RBRaspberryRuntimeHTTP404Error = notFound;
    RBRaspberryRuntimeLocalError = local;
    return YES;
}

static RBEndpoint * _Nullable RBRaspberryRuntimeLoadBundleEndpoint(void) {
    @try {
        NSURL *resourceURL = NSBundle.mainBundle.resourceURL;
        if (resourceURL == nil) {
            return nil;
        }
        NSURL *raspberryDirectoryURL =
            [resourceURL URLByAppendingPathComponent:@"raspberry"
                                         isDirectory:YES];
        NSURL *endpointFileURL =
            [raspberryDirectoryURL URLByAppendingPathComponent:@"endpoint.json"
                                                   isDirectory:NO];
        return RBRaspberryRuntimeLoadEndpointFromFileURL(endpointFileURL);
    } @catch (id exception) {
        (void)exception;
        return nil;
    }
}

static UIViewController * _Nullable RBRaspberryRuntimeResolveForegroundOwner(void) {
    if (![NSThread isMainThread]) {
        return nil;
    }
    UIApplication *application = UIApplication.sharedApplication;
    if (application == nil ||
        application.applicationState != UIApplicationStateActive) {
        return nil;
    }
    id<UIApplicationDelegate> delegate = application.delegate;
    UIWindow *window = nil;
    if ([delegate respondsToSelector:@selector(window)]) {
        window = delegate.window;
    }
    UIViewController *rootController = window.rootViewController;
    if (rootController == nil ||
        !RBAuthUIKitOwnerIsForeground(rootController, application, NULL)) {
        return nil;
    }
    return rootController;
}

static void RBRaspberryRuntimeStopOverlayPollTimer(void) {
    if (RBRaspberryRuntimeOverlayPollTimer != nil) {
        [RBRaspberryRuntimeOverlayPollTimer invalidate];
        RBRaspberryRuntimeOverlayPollTimer = nil;
    }
}

static BOOL RBRaspberryRuntimeSyncUIKitSignInGate(void) {
    if (![NSThread isMainThread] ||
        RBRaspberryRuntimeSessionController == nil ||
        RBRaspberryRuntimeSignInOverlay == nil) {
        return NO;
    }
    if (!RBRaspberryRuntimeSessionController.requiresSignInOverlay) {
        [RBRaspberryRuntimeSignInOverlay detachOverlay];
        RBRaspberryRuntimeStopOverlayPollTimer();
        return YES;
    }
    UIViewController *owner = RBRaspberryRuntimeResolveForegroundOwner();
    if (owner == nil) {
        return NO;
    }
    BOOL synced = [RBRaspberryRuntimeSignInOverlay syncWithForegroundOwner:owner];
    if (synced && RBRaspberryRuntimeSignInOverlay.isAttached) {
        RBRaspberryRuntimeStopOverlayPollTimer();
    }
    return synced;
}

static void RBRaspberryRuntimeInstallUIKitSignInGateOnMain(void) {
    if (![NSThread isMainThread] ||
        RBRaspberryRuntimeEndpoint == nil ||
        RBRaspberryRuntimeGate == nil) {
        return;
    }
    if (RBRaspberryRuntimeSessionController == nil) {
        RBRaspberryRuntimeSessionController = [[RBAuthSignInSessionController alloc]
            initWithEndpoint:RBRaspberryRuntimeEndpoint
              credentialGate:RBRaspberryRuntimeGate
              bindingFactory:^id<RBAuthSignInAttemptBinding> _Nullable(
                                 id<RBAuthFlowCommitter> committer) {
                  RBASWebAuthenticationSessionDriver *driver =
                      [[RBASWebAuthenticationSessionDriver alloc] init];
                  return [[RBAuthUIKitLifecycleBinding alloc]
                      initWithBrowserDriver:driver
                            exchangeFactory:^id<RBAuthFlowExchangeClient> _Nullable(
                                                RBAuthExchangeRequest *request) {
                                return (id<RBAuthFlowExchangeClient>)
                                    [[RBAuthExchangeClient alloc]
                                        initWithExchangeRequest:request];
                            }
                                  scheduler:nil
                               attemptClock:nil
                                  committer:committer];
              }];
    }
    if (RBRaspberryRuntimeSessionController == nil) {
        return;
    }
    if (RBRaspberryRuntimeSignInOverlay == nil) {
        RBRaspberryRuntimeSignInOverlay = [[RBAuthUIKitSignInOverlay alloc]
            initWithSessionController:RBRaspberryRuntimeSessionController];
    }
    if (RBRaspberryRuntimeSignInOverlay == nil) {
        return;
    }

    NSNotificationCenter *center = NSNotificationCenter.defaultCenter;
    if (RBRaspberryRuntimeDidBecomeActiveObserver == nil) {
        RBRaspberryRuntimeDidBecomeActiveObserver = [center
            addObserverForName:UIApplicationDidBecomeActiveNotification
                        object:nil
                         queue:NSOperationQueue.mainQueue
                    usingBlock:^(__unused NSNotification *notification) {
                        (void)RBRaspberryRuntimeSyncUIKitSignInGate();
                    }];
    }
    if (RBRaspberryRuntimeKeyWindowObserver == nil) {
        RBRaspberryRuntimeKeyWindowObserver = [center
            addObserverForName:UIWindowDidBecomeKeyNotification
                        object:nil
                         queue:NSOperationQueue.mainQueue
                    usingBlock:^(__unused NSNotification *notification) {
                        (void)RBRaspberryRuntimeSyncUIKitSignInGate();
                    }];
    }

    if (RBRaspberryRuntimeSyncUIKitSignInGate()) {
        return;
    }

    if (RBRaspberryRuntimeOverlayPollTimer == nil &&
        RBRaspberryRuntimeSessionController.requiresSignInOverlay) {
        RBRaspberryRuntimeOverlayPollAttempts = 0;
        RBRaspberryRuntimeOverlayPollTimer = [NSTimer
            timerWithTimeInterval:0.25
                          repeats:YES
                            block:^(__unused NSTimer *timer) {
                                RBRaspberryRuntimeOverlayPollAttempts++;
                                if (RBRaspberryRuntimeSyncUIKitSignInGate() ||
                                    RBRaspberryRuntimeOverlayPollAttempts >= 60) {
                                    RBRaspberryRuntimeStopOverlayPollTimer();
                                }
                            }];
        [[NSRunLoop mainRunLoop] addTimer:RBRaspberryRuntimeOverlayPollTimer
                                  forMode:NSRunLoopCommonModes];
    }
}

typedef id _Nullable (*RBWKWebViewLoadRequestIMP)(
    id self, SEL _cmd, NSURLRequest * _Nullable request);
typedef BOOL (*RBUIApplicationOpenURLIMP)(
    id self, SEL _cmd, NSURL * _Nullable url);
typedef void (*RBUIApplicationOpenURLWithOptionsIMP)(
    id self,
    SEL _cmd,
    NSURL * _Nullable url,
    NSDictionary * _Nullable options,
    void (^ _Nullable completion)(BOOL success));

static IMP RBRaspberryRuntimeOriginalWKWebViewLoadRequestIMP = NULL;
static IMP RBRaspberryRuntimeOriginalUIApplicationOpenURLIMP = NULL;
static IMP RBRaspberryRuntimeOriginalUIApplicationOpenURLWithOptionsIMP = NULL;

static RBEndpoint * _Nullable RBRaspberryRuntimeActiveEndpoint(void) {
    if (atomic_load_explicit(&RBRaspberryRuntimeReadiness,
            memory_order_acquire) != 1U ||
        !atomic_load_explicit(&RBRaspberryRuntimeHasEndpoint,
            memory_order_acquire)) {
        return nil;
    }
    return RBRaspberryRuntimeEndpoint;
}

static id _Nullable RBRaspberryRuntimeWKWebViewLoadRequest(
    id self, SEL _cmd, NSURLRequest * _Nullable request) {
    RBEndpoint *endpoint = RBRaspberryRuntimeActiveEndpoint();
    BOOL didRewrite = NO;
    BOOL blocked = NO;
    NSURLRequest *rewritten = [RBWebURLRouter rewrittenRequest:request
                                                      endpoint:endpoint
                                                    didRewrite:&didRewrite
                                                       blocked:&blocked];
    if (blocked) {
        return nil;
    }
    RBWKWebViewLoadRequestIMP original =
        (RBWKWebViewLoadRequestIMP)RBRaspberryRuntimeOriginalWKWebViewLoadRequestIMP;
    if (original == NULL) {
        return nil;
    }
    return original(self, _cmd, didRewrite ? rewritten : request);
}

static BOOL RBRaspberryRuntimeUIApplicationOpenURL(
    id self, SEL _cmd, NSURL * _Nullable url) {
    RBEndpoint *endpoint = RBRaspberryRuntimeActiveEndpoint();
    BOOL didRewrite = NO;
    BOOL blocked = NO;
    NSURL *rewritten = [RBWebURLRouter rewrittenExternalURL:url
                                                   endpoint:endpoint
                                                 didRewrite:&didRewrite
                                                    blocked:&blocked];
    if (blocked) {
        return NO;
    }
    RBUIApplicationOpenURLIMP original =
        (RBUIApplicationOpenURLIMP)RBRaspberryRuntimeOriginalUIApplicationOpenURLIMP;
    if (original == NULL) {
        return NO;
    }
    return original(self, _cmd, didRewrite ? rewritten : url);
}

static void RBRaspberryRuntimeUIApplicationOpenURLWithOptions(
    id self,
    SEL _cmd,
    NSURL * _Nullable url,
    NSDictionary * _Nullable options,
    void (^ _Nullable completion)(BOOL success)) {
    RBEndpoint *endpoint = RBRaspberryRuntimeActiveEndpoint();
    BOOL didRewrite = NO;
    BOOL blocked = NO;
    NSURL *rewritten = [RBWebURLRouter rewrittenExternalURL:url
                                                   endpoint:endpoint
                                                 didRewrite:&didRewrite
                                                    blocked:&blocked];
    if (blocked) {
        if (completion != nil) {
            void (^completionCopy)(BOOL success) = [completion copy];
            dispatch_async(dispatch_get_main_queue(), ^{
                completionCopy(NO);
            });
        }
        return;
    }
    RBUIApplicationOpenURLWithOptionsIMP original =
        (RBUIApplicationOpenURLWithOptionsIMP)
            RBRaspberryRuntimeOriginalUIApplicationOpenURLWithOptionsIMP;
    if (original == NULL) {
        if (completion != nil) {
            void (^completionCopy)(BOOL success) = [completion copy];
            dispatch_async(dispatch_get_main_queue(), ^{
                completionCopy(NO);
            });
        }
        return;
    }
    original(self, _cmd, didRewrite ? rewritten : url, options, completion);
}

static BOOL RBRaspberryRuntimeSwizzleInstanceMethod(
    Class targetClass,
    SEL selector,
    IMP replacement,
    IMP _Nullable * _Nonnull originalSlot) {
    if (targetClass == Nil || selector == NULL || replacement == NULL ||
        originalSlot == NULL) {
        return NO;
    }
    Method method = class_getInstanceMethod(targetClass, selector);
    if (method == NULL) {
        return NO;
    }
    const char *encoding = method_getTypeEncoding(method);
    IMP current = method_getImplementation(method);
    if (encoding == NULL || current == NULL) {
        return NO;
    }
    *originalSlot = current;
    if (!class_addMethod(targetClass, selector, replacement, encoding)) {
        IMP previous = method_setImplementation(method, replacement);
        if (previous == NULL) {
            return NO;
        }
        *originalSlot = previous;
    }
    return YES;
}

static BOOL RBRaspberryRuntimeInstallWebURLSwizzles(void) {
    static dispatch_once_t onceToken;
    static BOOL installed = NO;
    dispatch_once(&onceToken, ^{
        Class wkWebViewClass = (Class)objc_getClass("WKWebView");
        Class uiApplicationClass = (Class)objc_getClass("UIApplication");
        if (wkWebViewClass == Nil || uiApplicationClass == Nil) {
            return;
        }
        if (!RBRaspberryRuntimeSwizzleInstanceMethod(
                wkWebViewClass,
                sel_registerName("loadRequest:"),
                (IMP)RBRaspberryRuntimeWKWebViewLoadRequest,
                &RBRaspberryRuntimeOriginalWKWebViewLoadRequestIMP) ||
            !RBRaspberryRuntimeSwizzleInstanceMethod(
                uiApplicationClass,
                sel_registerName("openURL:"),
                (IMP)RBRaspberryRuntimeUIApplicationOpenURL,
                &RBRaspberryRuntimeOriginalUIApplicationOpenURLIMP) ||
            !RBRaspberryRuntimeSwizzleInstanceMethod(
                uiApplicationClass,
                sel_registerName("openURL:options:completionHandler:"),
                (IMP)RBRaspberryRuntimeUIApplicationOpenURLWithOptions,
                &RBRaspberryRuntimeOriginalUIApplicationOpenURLWithOptionsIMP)) {
            return;
        }
        installed = YES;
    });
    return installed;
}

static BOOL RBRaspberryRuntimeInitialize(void) {
    RBRaspberryRuntimeMainImage mainImage = {0};
    if (!RBRaspberryRuntimeFindUniqueMainImage(&mainImage)) {
        return NO;
    }

    Class noticeCenterClass = (Class)objc_getClass("LCHTTPRequestCenter");
    Class errorClass = (Class)objc_getClass("LCError");
    if (noticeCenterClass == Nil || errorClass == Nil) {
        return NO;
    }

    SEL requestSelector = sel_registerName("requestDataWithURL:name:");
    SEL userAgentSelector = sel_registerName("userAgent");
    SEL errorFactorySelector = sel_registerName("errorWithType:domain:code:");
    IMP requestImplementation = NULL;
    IMP userAgentImplementation = NULL;
    IMP errorFactoryImplementation = NULL;
    if (!RBRaspberryRuntimeMethodMatches(noticeCenterClass, requestSelector,
            "@32@0:8@16@24", RBRaspberryRuntimeRequestMethodRVA,
            &mainImage, &requestImplementation) ||
        !RBRaspberryRuntimeMethodMatches(noticeCenterClass, userAgentSelector,
            "@16@0:8", RBRaspberryRuntimeUserAgentRVA,
            &mainImage, &userAgentImplementation) ||
        !RBRaspberryRuntimeMethodMatches(errorClass, errorFactorySelector,
            "@40@0:8Q16@24q32", RBRaspberryRuntimeLCErrorFactoryRVA,
            &mainImage, &errorFactoryImplementation)) {
        return NO;
    }
    if ((uintptr_t)requestImplementation !=
            (uintptr_t)mainImage.header + RBRaspberryRuntimeRequestMethodRVA ||
        (uintptr_t)userAgentImplementation !=
            (uintptr_t)mainImage.header + RBRaspberryRuntimeUserAgentRVA ||
        (uintptr_t)errorFactoryImplementation !=
            (uintptr_t)mainImage.header + RBRaspberryRuntimeLCErrorFactoryRVA) {
        return NO;
    }

    if (!RBRaspberryRuntimePrepareErrors(errorClass, errorFactorySelector,
            errorFactoryImplementation, &mainImage)) {
        return NO;
    }

    if ((uintptr_t)mainImage.header >
        UINTPTR_MAX - RBRaspberryRuntimeContinuationRVA) {
        return NO;
    }

    RBEndpoint *endpoint = RBRaspberryRuntimeLoadBundleEndpoint();
    const rb_socket_ops *ops = RBRaspberryRuntimeFallbackOps();
    if (ops == NULL) {
        return NO;
    }
    rb_config routerConfig;
    const rb_config *routerConfigPtr = NULL;
    if (endpoint != nil) {
        routerConfig = [endpoint copyOutRBConfig];
        routerConfigPtr = &routerConfig;
    }
    if (rb_router_init(&RBRaspberryRuntimeSocketRouter, ops,
            routerConfigPtr) != 0) {
        return NO;
    }

    NSURL *appSupportURL = [NSFileManager.defaultManager
        URLsForDirectory:NSApplicationSupportDirectory
               inDomains:NSUserDomainMask].firstObject;
    NSURL *cachesURL = [NSFileManager.defaultManager
        URLsForDirectory:NSCachesDirectory
               inDomains:NSUserDomainMask].firstObject;
    RBAuthGuestCredentialGate *gate = RBRaspberryRuntimeInitializeGate(
        endpoint, appSupportURL, cachesURL);

    RBRaspberryRuntimeMainImageInfo = mainImage;
    RBRaspberryRuntimeNoticeCenterClass = noticeCenterClass;
    RBRaspberryRuntimeUserAgentSelector = userAgentSelector;
    RBRaspberryRuntimeUserAgentExpectedIMP = userAgentImplementation;
    RBRaspberryRuntimeExpectedReceiver = noticeCenterClass;
    RBRaspberryRuntimeExpectedSelector = requestSelector;
    RBRaspberryRuntimeExpectedContinuation =
        (uintptr_t)mainImage.header + RBRaspberryRuntimeContinuationRVA;
    RBRaspberryRuntimeEndpoint = endpoint;
    RBRaspberryRuntimeGate = gate;
    atomic_store_explicit(&RBRaspberryRuntimeAttemptedOnce, false,
                          memory_order_release);

    if (!RBRaspberryRuntimeInstallWebURLSwizzles()) {
        rb_router_destroy(&RBRaspberryRuntimeSocketRouter);
        return NO;
    }

    atomic_store_explicit(&RBRaspberryRuntimeHasEndpoint, endpoint != nil,
                          memory_order_release);
    atomic_store_explicit(&RBRaspberryRuntimeRouterInitialized, 1U,
                          memory_order_release);
    atomic_store_explicit(&RBRaspberryRuntimeReadiness, 1U, memory_order_release);

    if (endpoint != nil && gate != nil) {
        dispatch_async(dispatch_get_main_queue(), ^{
            RBRaspberryRuntimeInstallUIKitSignInGateOnMain();
        });
    }
    return YES;
}

static void RBRaspberryRuntimeConstructor(void) __attribute__((constructor));

static void RBRaspberryRuntimeConstructor(void) {
    @try {
        if (!RBRaspberryRuntimeInitialize()) {
            __builtin_trap();
        }
    } @catch (id exception) {
        (void)exception;
        __builtin_trap();
    }
}

static NSString * _Nullable RBRaspberryRuntimeReadStockUserAgent(
    id __unsafe_unretained receiver) {
    (void)receiver;
    IMP currentIMP = NULL;
    if (RBRaspberryRuntimeNoticeCenterClass == Nil ||
        RBRaspberryRuntimeUserAgentSelector == NULL ||
        !RBRaspberryRuntimeMethodMatches(RBRaspberryRuntimeNoticeCenterClass,
            RBRaspberryRuntimeUserAgentSelector,
            "@16@0:8",
            RBRaspberryRuntimeUserAgentRVA,
            &RBRaspberryRuntimeMainImageInfo,
            &currentIMP) ||
        currentIMP != RBRaspberryRuntimeUserAgentExpectedIMP) {
        return nil;
    }
    @try {
        id candidate = RBRaspberryRuntimeSendUserAgent(
            RBRaspberryRuntimeNoticeCenterClass,
            RBRaspberryRuntimeUserAgentSelector);
        return RBRaspberryRuntimeValidatedUserAgent(candidate);
    } @catch (id exception) {
        (void)exception;
        return nil;
    }
}

__attribute__((visibility("default"), used, ns_returns_not_retained))
id rb_ios_notice_404_diagnostic_entry(
    id __unsafe_unretained receiver,
    SEL selector,
    id __unsafe_unretained URL,
    id __unsafe_unretained name,
    uintptr_t callerLR) {
    if (atomic_load_explicit(&RBRaspberryRuntimeReadiness,
            memory_order_acquire) != 1U) {
        __builtin_trap();
    }

    NSString *sourceURLString = nil;
    BOOL argumentsMatch = NO;
    @try {
        argumentsMatch = RBRaspberryRuntimeArgumentsMatch(receiver, selector,
            URL, name, callerLR, &sourceURLString);
    } @catch (id exception) {
        (void)exception;
        __builtin_trap();
    }

    if (!argumentsMatch || sourceURLString == nil) {
        return RBRaspberryRuntimeFailClosed();
    }

    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(
            &RBRaspberryRuntimeAttemptedOnce, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) {
        return RBRaspberryRuntimeFailClosed();
    }

    RBEndpoint *endpoint = RBRaspberryRuntimeEndpoint;
    if (endpoint == nil) {
        return RBRaspberryRuntimeFailClosed();
    }

    NSString *stockUserAgent = RBRaspberryRuntimeReadStockUserAgent(receiver);
    id HTTP404Error = RBRaspberryRuntimeHTTP404Error;
    id localError = RBRaspberryRuntimeLocalError;
    if (HTTP404Error == nil || localError == nil) {
        __builtin_trap();
    }

    RBNoticeRouteClient *client = [[RBNoticeRouteClient alloc]
        initWithStockURLString:sourceURLString
                      endpoint:endpoint
                     userAgent:stockUserAgent];

    RBNoticeRouteErrorAdapter *adapter = [[RBNoticeRouteErrorAdapter alloc]
        initWithOwnedClient:client
           fakeErrorFactory:^id _Nullable(RBNoticeRouteErrorKind kind) {
               return kind == RBNoticeRouteErrorKindHTTP404
                   ? HTTP404Error
                   : localError;
           }];

    RBNoticeRouteErrorKind kind = RBNoticeRouteErrorKindInvalidRequest;
    id result = nil;
    if (adapter != nil) {
        @try {
            result = [adapter performSynchronouslyWithErrorKind:&kind];
        } @catch (id exception) {
            (void)exception;
            result = nil;
        }
    }
    (void)kind;

    if (result == HTTP404Error) {
        return HTTP404Error;
    }
    return localError;
}

__attribute__((visibility("default"), used))
int rb_ios_getaddrinfo(
    const char *node,
    const char *service,
    const struct addrinfo *hints,
    struct addrinfo **res) {
    bool isRedirect = (node != NULL && rb_redirect(node) != 0);
    if (atomic_load_explicit(&RBRaspberryRuntimeRouterInitialized,
            memory_order_acquire) != 1U) {
        if (isRedirect) {
            if (res != NULL) {
                *res = NULL;
            }
            return EAI_FAIL;
        }
        const rb_socket_ops *ops = RBRaspberryRuntimeFallbackOps();
        if (ops == NULL || ops->real_getaddrinfo == NULL) {
            if (res != NULL) {
                *res = NULL;
            }
            return EAI_FAIL;
        }
        return ops->real_getaddrinfo(node, service, hints, res);
    }

    bool hasEndpoint = atomic_load_explicit(&RBRaspberryRuntimeHasEndpoint,
        memory_order_acquire);
    if (isRedirect && !hasEndpoint) {
        if (res != NULL) {
            *res = NULL;
        }
        return EAI_FAIL;
    }

    return rb_router_getaddrinfo(
        &RBRaspberryRuntimeSocketRouter, node, service, hints, res);
}

__attribute__((visibility("default"), used))
void rb_ios_freeaddrinfo(struct addrinfo *res) {
    if (res == NULL) {
        return;
    }
    if (atomic_load_explicit(&RBRaspberryRuntimeRouterInitialized,
            memory_order_acquire) != 1U) {
        const rb_socket_ops *ops = RBRaspberryRuntimeFallbackOps();
        if (ops != NULL && ops->real_freeaddrinfo != NULL) {
            ops->real_freeaddrinfo(res);
        }
        return;
    }
    rb_router_freeaddrinfo(&RBRaspberryRuntimeSocketRouter, res);
}

__attribute__((visibility("default"), used))
struct hostent *rb_ios_gethostbyname(const char *name) {
    bool isRedirect = (name != NULL && rb_redirect(name) != 0);
    if (atomic_load_explicit(&RBRaspberryRuntimeRouterInitialized,
            memory_order_acquire) != 1U) {
        if (isRedirect) {
            h_errno = HOST_NOT_FOUND;
            return NULL;
        }
        const rb_socket_ops *ops = RBRaspberryRuntimeFallbackOps();
        if (ops == NULL || ops->real_gethostbyname == NULL) {
            h_errno = NO_RECOVERY;
            return NULL;
        }
        return ops->real_gethostbyname(name);
    }

    bool hasEndpoint = atomic_load_explicit(&RBRaspberryRuntimeHasEndpoint,
        memory_order_acquire);
    if (isRedirect && !hasEndpoint) {
        h_errno = HOST_NOT_FOUND;
        return NULL;
    }

    return rb_router_gethostbyname(&RBRaspberryRuntimeSocketRouter, name);
}

__attribute__((visibility("default"), used))
int rb_ios_connect(
    int sockfd,
    const struct sockaddr *addr,
    socklen_t addrlen) {
    bool isMarker = RBRaspberryRuntimeIsMarkerIPv4(addr, addrlen);
    if (atomic_load_explicit(&RBRaspberryRuntimeRouterInitialized,
            memory_order_acquire) != 1U) {
        if (isMarker) {
            errno = EHOSTUNREACH;
            return -1;
        }
        const rb_socket_ops *ops = RBRaspberryRuntimeFallbackOps();
        if (ops == NULL || ops->real_connect == NULL) {
            errno = EHOSTUNREACH;
            return -1;
        }
        return ops->real_connect(sockfd, addr, addrlen);
    }

    bool hasEndpoint = atomic_load_explicit(&RBRaspberryRuntimeHasEndpoint,
        memory_order_acquire);
    if (isMarker && !hasEndpoint) {
        errno = EHOSTUNREACH;
        return -1;
    }

    return rb_router_connect(
        &RBRaspberryRuntimeSocketRouter, sockfd, addr, addrlen);
}

__attribute__((visibility("default"), used))
const char * _Nullable rb_ios_guest_unique_code(
    void * _Nullable invoker,
    const char * _Nullable stockUniqueCode) {
    (void)invoker;
    (void)stockUniqueCode;

    if (atomic_load_explicit(&RBRaspberryRuntimeReadiness,
            memory_order_acquire) != 1U) {
        __builtin_trap();
    }

    BOOL hasEndpoint = atomic_load_explicit(&RBRaspberryRuntimeHasEndpoint,
        memory_order_acquire);
    RBAuthGuestCredentialGate *gate = RBRaspberryRuntimeGate;
    return (hasEndpoint && gate != nil)
        ? [gate authorizedUniqueCodeUTF8]
        : NULL;
}
