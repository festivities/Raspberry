#import "RBAuthStore.h"

#import "RBEndpoint.h"

#import <CoreFoundation/CoreFoundation.h>
#import <errno.h>
#import <fcntl.h>
#import <limits.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

NSString *const RBAuthStoreErrorDomain = @"org.raspberry.auth-store";

enum {
    RBAuthStoreMaxFileBytes = 1024,
    RBAuthStoreMaxOriginLength = 512,
    RBAuthStoreTempAttempts = 16,
};

static const char RBAuthStoreSubdirName[] = "raspberry";
static const char RBAuthStoreFileName[] = "auth.json";
static const char RBAuthStoreCookieName[] = "avcookie.na";

static NSError *RBMakeStoreError(RBAuthStoreErrorCode code, NSString *message) {
    return [NSError errorWithDomain:RBAuthStoreErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey : message}];
}

static void RBSetStoreError(NSError * _Nullable * _Nullable outError,
                            RBAuthStoreErrorCode code,
                            NSString *message) {
    if (outError != NULL) {
        *outError = RBMakeStoreError(code, message);
    }
}

static NSString * _Nullable RBValidatedDirectoryPath(NSURL * _Nullable url) {
    if (url == nil || !url.isFileURL || url.path.length == 0) {
        return nil;
    }
    const char *raw = NULL;
    @try {
        raw = url.fileSystemRepresentation;
    } @catch (NSException *exception) {
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
    return [[NSString alloc] initWithBytes:raw length:len encoding:NSUTF8StringEncoding];
}

static BOOL RBIsCanonicalLowercaseUUID(NSString * _Nullable value) {
    if (![value isKindOfClass:[NSString class]] || value.length != 36) {
        return NO;
    }
    for (NSUInteger i = 0; i < value.length; i++) {
        unichar c = [value characterAtIndex:i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') {
                return NO;
            }
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return NO;
        }
    }
    return YES;
}

static BOOL RBIsValidOrigin(NSString * _Nullable origin) {
    if (![origin isKindOfClass:[NSString class]] || origin.length == 0 ||
        origin.length > RBAuthStoreMaxOriginLength || ![origin hasPrefix:@"https://"]) {
        return NO;
    }
    for (NSUInteger i = 0; i < origin.length; i++) {
        unichar c = [origin characterAtIndex:i];
        if (c < 0x21 || c > 0x7E) {
            return NO;
        }
    }
    if ([origin rangeOfString:@"/" options:0 range:NSMakeRange(8, origin.length - 8)].location !=
            NSNotFound ||
        [origin containsString:@"?"] || [origin containsString:@"#"]) {
        return NO;
    }
    NSURLComponents *components = [NSURLComponents componentsWithString:origin];
    if (components == nil || ![components.scheme isEqualToString:@"https"] ||
        components.host.length == 0 || components.user != nil || components.password != nil ||
        components.path.length != 0 || components.query != nil || components.fragment != nil ||
        ![components.string isEqualToString:origin]) {
        return NO;
    }
    if (components.port != nil) {
        NSInteger port = components.port.integerValue;
        if (port < 1 || port > 65535) {
            return NO;
        }
    }
    return YES;
}

static BOOL RBIsExactVersionOne(id _Nullable value) {
    if (![value isKindOfClass:[NSNumber class]]) {
        return NO;
    }
    NSNumber *number = (NSNumber *)value;
    if (CFGetTypeID((__bridge CFTypeRef)number) == CFBooleanGetTypeID()) {
        return NO;
    }
    const char *type = number.objCType;
    if (type != NULL && (type[0] == 'f' || type[0] == 'd')) {
        return NO;
    }
    return [number.stringValue isEqualToString:@"1"];
}

static int RBOpenSecureDirectoryPath(const char *path,
                                     RBAuthStoreErrorCode * _Nullable outCode,
                                     NSString * _Nullable * _Nullable outMessage) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            if (outCode != NULL) {
                *outCode = RBAuthStoreErrorNotFound;
            }
            if (outMessage != NULL) {
                *outMessage = @"auth store: directory not found";
            }
        } else if (errno == ELOOP || errno == ENOTDIR) {
            if (outCode != NULL) {
                *outCode = RBAuthStoreErrorCorrupt;
            }
            if (outMessage != NULL) {
                *outMessage = @"auth store: unsafe directory";
            }
        } else {
            if (outCode != NULL) {
                *outCode = RBAuthStoreErrorIO;
            }
            if (outMessage != NULL) {
                *outMessage = @"auth store: directory open failed";
            }
        }
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        if (outCode != NULL) {
            *outCode = RBAuthStoreErrorIO;
        }
        if (outMessage != NULL) {
            *outMessage = @"auth store: directory stat failed";
        }
        return -1;
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(fd);
        if (outCode != NULL) {
            *outCode = RBAuthStoreErrorCorrupt;
        }
        if (outMessage != NULL) {
            *outMessage = @"auth store: unsafe directory permissions";
        }
        return -1;
    }
    return fd;
}

static int RBOpenSecureSubdirectory(int parentFD,
                                    const char *name,
                                    BOOL createIfMissing,
                                    RBAuthStoreErrorCode * _Nullable outCode,
                                    NSString * _Nullable * _Nullable outMessage) {
    int fd = openat(parentFD, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT && createIfMissing) {
        if (mkdirat(parentFD, name, 0700) != 0 && errno != EEXIST) {
            if (outCode != NULL) {
                *outCode = RBAuthStoreErrorIO;
            }
            if (outMessage != NULL) {
                *outMessage = @"auth store: directory creation failed";
            }
            return -1;
        }
        fd = openat(parentFD, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
    if (fd < 0) {
        if (errno == ENOENT) {
            if (outCode != NULL) {
                *outCode = RBAuthStoreErrorNotFound;
            }
            if (outMessage != NULL) {
                *outMessage = @"auth store: authorization not found";
            }
        } else if (errno == ELOOP || errno == ENOTDIR) {
            if (outCode != NULL) {
                *outCode = RBAuthStoreErrorCorrupt;
            }
            if (outMessage != NULL) {
                *outMessage = @"auth store: unsafe subdirectory";
            }
        } else {
            if (outCode != NULL) {
                *outCode = RBAuthStoreErrorIO;
            }
            if (outMessage != NULL) {
                *outMessage = @"auth store: subdirectory open failed";
            }
        }
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        if (outCode != NULL) {
            *outCode = RBAuthStoreErrorIO;
        }
        if (outMessage != NULL) {
            *outMessage = @"auth store: subdirectory stat failed";
        }
        return -1;
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(fd);
        if (outCode != NULL) {
            *outCode = RBAuthStoreErrorCorrupt;
        }
        if (outMessage != NULL) {
            *outMessage = @"auth store: unsafe subdirectory permissions";
        }
        return -1;
    }
    if (createIfMissing && (st.st_mode & 0777) != 0700) {
        if (fchmod(fd, 0700) != 0) {
            close(fd);
            if (outCode != NULL) {
                *outCode = RBAuthStoreErrorIO;
            }
            if (outMessage != NULL) {
                *outMessage = @"auth store: subdirectory chmod failed";
            }
            return -1;
        }
    }
    return fd;
}

static BOOL RBWriteAll(int fd, const uint8_t *bytes, size_t length) {
    size_t written = 0;
    while (written < length) {
        ssize_t n = write(fd, bytes + written, length - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return NO;
        }
        if (n == 0) {
            return NO;
        }
        written += (size_t)n;
    }
    return YES;
}

@interface RBAuthStore () {
    NSString *_basePath;
    NSString *_cachesPath;
}
@end

@implementation RBAuthStore

- (nullable instancetype)initWithBaseDirectoryURL:(nullable NSURL *)baseDirectoryURL
                               cachesDirectoryURL:(nullable NSURL *)cachesDirectoryURL {
    NSString *basePath = RBValidatedDirectoryPath(baseDirectoryURL);
    NSString *cachesPath = RBValidatedDirectoryPath(cachesDirectoryURL);
    if (basePath == nil || cachesPath == nil) {
        return nil;
    }
    self = [super init];
    if (self != nil) {
        _basePath = [basePath copy];
        _cachesPath = [cachesPath copy];
    }
    return self;
}

- (nullable NSString *)authorizedUniqueCodeForEndpoint:(nullable RBEndpoint *)endpoint
                                                 error:(NSError * _Nullable * _Nullable)error {
    if (error != NULL) {
        *error = nil;
    }
    if (endpoint == nil || !RBIsValidOrigin(endpoint.httpsOrigin)) {
        RBSetStoreError(error, RBAuthStoreErrorInvalidInput, @"auth store: invalid endpoint");
        return nil;
    }

    @synchronized(self) {
        RBAuthStoreErrorCode openCode = RBAuthStoreErrorIO;
        NSString *openMsg = nil;
        int baseFD = RBOpenSecureDirectoryPath(_basePath.fileSystemRepresentation, &openCode, &openMsg);
        if (baseFD < 0) {
            if (openCode == RBAuthStoreErrorNotFound) {
                RBSetStoreError(error, RBAuthStoreErrorNotFound, @"auth store: authorization not found");
            } else {
                RBSetStoreError(error, openCode, openMsg);
            }
            return nil;
        }

        int raspFD = RBOpenSecureSubdirectory(baseFD, RBAuthStoreSubdirName, NO, &openCode, &openMsg);
        close(baseFD);
        if (raspFD < 0) {
            RBSetStoreError(error, openCode, openMsg);
            return nil;
        }

        int fileFD = openat(raspFD, RBAuthStoreFileName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        close(raspFD);
        if (fileFD < 0) {
            if (errno == ENOENT) {
                RBSetStoreError(error, RBAuthStoreErrorNotFound, @"auth store: authorization not found");
            } else if (errno == ELOOP || errno == EISDIR) {
                RBSetStoreError(error, RBAuthStoreErrorCorrupt, @"auth store: unsafe authorization file");
            } else {
                RBSetStoreError(error, RBAuthStoreErrorIO, @"auth store: authorization read failed");
            }
            return nil;
        }

        struct stat st;
        if (fstat(fileFD, &st) != 0) {
            close(fileFD);
            RBSetStoreError(error, RBAuthStoreErrorIO, @"auth store: authorization stat failed");
            return nil;
        }
        if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0077) != 0 ||
            st.st_size <= 0 || st.st_size > RBAuthStoreMaxFileBytes) {
            close(fileFD);
            RBSetStoreError(error, RBAuthStoreErrorCorrupt, @"auth store: invalid authorization file");
            return nil;
        }

        uint8_t buffer[RBAuthStoreMaxFileBytes + 1];
        size_t total = 0;
        while (total < sizeof(buffer)) {
            ssize_t n = read(fileFD, buffer + total, sizeof(buffer) - total);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                close(fileFD);
                RBSetStoreError(error, RBAuthStoreErrorIO, @"auth store: authorization read failed");
                return nil;
            }
            if (n == 0) {
                break;
            }
            total += (size_t)n;
        }
        close(fileFD);

        if (total == 0 || total > RBAuthStoreMaxFileBytes) {
            RBSetStoreError(error, RBAuthStoreErrorCorrupt, @"auth store: invalid authorization size");
            return nil;
        }

        NSData *data = [NSData dataWithBytes:buffer length:total];
        id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
        if (![object isKindOfClass:[NSDictionary class]]) {
            RBSetStoreError(error, RBAuthStoreErrorCorrupt, @"auth store: corrupt authorization JSON");
            return nil;
        }

        NSDictionary *dict = (NSDictionary *)object;
        if (dict.count != 3 || !RBIsExactVersionOne(dict[@"v"])) {
            RBSetStoreError(error, RBAuthStoreErrorCorrupt, @"auth store: corrupt authorization schema");
            return nil;
        }

        id rawOrigin = dict[@"origin"];
        id rawCode = dict[@"uniqueCode"];
        if (![rawOrigin isKindOfClass:[NSString class]] || !RBIsValidOrigin((NSString *)rawOrigin) ||
            ![rawCode isKindOfClass:[NSString class]] || !RBIsCanonicalLowercaseUUID((NSString *)rawCode)) {
            RBSetStoreError(error, RBAuthStoreErrorCorrupt, @"auth store: corrupt authorization fields");
            return nil;
        }

        NSString *storedOrigin = (NSString *)rawOrigin;
        if (![storedOrigin isEqualToString:endpoint.httpsOrigin]) {
            RBSetStoreError(error, RBAuthStoreErrorOriginMismatch, @"auth store: origin mismatch");
            return nil;
        }

        return [(NSString *)rawCode copy];
    }
}

- (BOOL)commitUniqueCode:(nullable NSString *)uniqueCode
             forEndpoint:(nullable RBEndpoint *)endpoint
                   error:(NSError * _Nullable * _Nullable)error {
    if (error != NULL) {
        *error = nil;
    }
    if (!RBIsCanonicalLowercaseUUID(uniqueCode) || endpoint == nil ||
        !RBIsValidOrigin(endpoint.httpsOrigin)) {
        RBSetStoreError(error, RBAuthStoreErrorInvalidInput, @"auth store: invalid commit input");
        return NO;
    }

    NSDictionary *payload = @{
        @"v" : @1,
        @"origin" : [endpoint.httpsOrigin copy],
        @"uniqueCode" : [uniqueCode copy],
    };
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:payload
                                                       options:NSJSONWritingSortedKeys |
                                                               NSJSONWritingWithoutEscapingSlashes
                                                         error:NULL];
    if (jsonData == nil || jsonData.length == 0 || jsonData.length > RBAuthStoreMaxFileBytes) {
        RBSetStoreError(error, RBAuthStoreErrorInvalidInput, @"auth store: invalid authorization payload");
        return NO;
    }

    @synchronized(self) {
        RBAuthStoreErrorCode dirCode = RBAuthStoreErrorIO;
        NSString *dirMsg = nil;
        int baseFD = RBOpenSecureDirectoryPath(_basePath.fileSystemRepresentation, &dirCode, &dirMsg);
        if (baseFD < 0) {
            RBSetStoreError(error,
                            dirCode == RBAuthStoreErrorNotFound ? RBAuthStoreErrorIO : dirCode,
                            dirMsg);
            return NO;
        }

        int raspFD = RBOpenSecureSubdirectory(baseFD, RBAuthStoreSubdirName, YES, &dirCode, &dirMsg);
        close(baseFD);
        if (raspFD < 0) {
            RBSetStoreError(error, dirCode, dirMsg);
            return NO;
        }

        struct stat existingAuth;
        if (fstatat(raspFD, RBAuthStoreFileName, &existingAuth, AT_SYMLINK_NOFOLLOW) == 0) {
            if (!S_ISREG(existingAuth.st_mode)) {
                close(raspFD);
                RBSetStoreError(error, RBAuthStoreErrorCorrupt, @"auth store: unsafe authorization file");
                return NO;
            }
        } else if (errno != ENOENT) {
            close(raspFD);
            RBSetStoreError(error, RBAuthStoreErrorIO, @"auth store: authorization stat failed");
            return NO;
        }

        int cachesFD = RBOpenSecureDirectoryPath(_cachesPath.fileSystemRepresentation, &dirCode, &dirMsg);
        if (cachesFD < 0) {
            close(raspFD);
            RBSetStoreError(error,
                            dirCode == RBAuthStoreErrorNotFound ? RBAuthStoreErrorIO : dirCode,
                            dirMsg);
            return NO;
        }

        struct stat cookieSt;
        if (fstatat(cachesFD, RBAuthStoreCookieName, &cookieSt, AT_SYMLINK_NOFOLLOW) == 0) {
            if (!S_ISREG(cookieSt.st_mode)) {
                close(cachesFD);
                close(raspFD);
                RBSetStoreError(error, RBAuthStoreErrorCorrupt, @"auth store: unsafe cache file");
                return NO;
            }
            if (unlinkat(cachesFD, RBAuthStoreCookieName, 0) != 0 && errno != ENOENT) {
                close(cachesFD);
                close(raspFD);
                RBSetStoreError(error, RBAuthStoreErrorIO, @"auth store: cache cleanup failed");
                return NO;
            }
        } else if (errno != ENOENT) {
            close(cachesFD);
            close(raspFD);
            RBSetStoreError(error, RBAuthStoreErrorIO, @"auth store: cache stat failed");
            return NO;
        }
        close(cachesFD);

        char tempName[64];
        int tempFD = -1;
        for (int attempt = 0; attempt < RBAuthStoreTempAttempts; attempt++) {
            snprintf(tempName, sizeof(tempName), ".auth.json.tmp.%08x%08x",
                     arc4random(), arc4random());
            tempFD = openat(raspFD, tempName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                            0600);
            if (tempFD >= 0 || errno != EEXIST) {
                break;
            }
        }
        if (tempFD < 0) {
            close(raspFD);
            RBSetStoreError(error, RBAuthStoreErrorIO, @"auth store: temporary file creation failed");
            return NO;
        }

        struct stat tempSt;
        if (fchmod(tempFD, 0600) != 0 || fstat(tempFD, &tempSt) != 0 || !S_ISREG(tempSt.st_mode) ||
            tempSt.st_uid != geteuid() || (tempSt.st_mode & 0077) != 0) {
            close(tempFD);
            unlinkat(raspFD, tempName, 0);
            close(raspFD);
            RBSetStoreError(error, RBAuthStoreErrorIO, @"auth store: temporary file permissions failed");
            return NO;
        }

        if (!RBWriteAll(tempFD, jsonData.bytes, jsonData.length) || fsync(tempFD) != 0) {
            close(tempFD);
            unlinkat(raspFD, tempName, 0);
            close(raspFD);
            RBSetStoreError(error, RBAuthStoreErrorIO, @"auth store: temporary file write failed");
            return NO;
        }
        if (close(tempFD) != 0) {
            unlinkat(raspFD, tempName, 0);
            close(raspFD);
            RBSetStoreError(error, RBAuthStoreErrorIO, @"auth store: temporary file close failed");
            return NO;
        }

        if (renameat(raspFD, tempName, raspFD, RBAuthStoreFileName) != 0) {
            unlinkat(raspFD, tempName, 0);
            close(raspFD);
            RBSetStoreError(error, RBAuthStoreErrorIO, @"auth store: authorization commit rename failed");
            return NO;
        }
        if (fsync(raspFD) != 0) {
            close(raspFD);
            RBSetStoreError(error, RBAuthStoreErrorIO, @"auth store: directory sync failed");
            return NO;
        }
        close(raspFD);
        return YES;
    }
}

- (BOOL)clearAuthorizationError:(NSError * _Nullable * _Nullable)error {
    if (error != NULL) {
        *error = nil;
    }

    @synchronized(self) {
        RBAuthStoreErrorCode openCode = RBAuthStoreErrorIO;
        NSString *openMsg = nil;
        int baseFD = RBOpenSecureDirectoryPath(_basePath.fileSystemRepresentation, &openCode, &openMsg);
        if (baseFD < 0) {
            if (openCode == RBAuthStoreErrorNotFound) {
                return YES;
            }
            RBSetStoreError(error, openCode, openMsg);
            return NO;
        }

        int raspFD = RBOpenSecureSubdirectory(baseFD, RBAuthStoreSubdirName, NO, &openCode, &openMsg);
        close(baseFD);
        if (raspFD < 0) {
            if (openCode == RBAuthStoreErrorNotFound) {
                return YES;
            }
            RBSetStoreError(error, openCode, openMsg);
            return NO;
        }

        struct stat st;
        if (fstatat(raspFD, RBAuthStoreFileName, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            int err = errno;
            close(raspFD);
            if (err == ENOENT) {
                return YES;
            }
            RBSetStoreError(error, RBAuthStoreErrorIO, @"auth store: authorization stat failed");
            return NO;
        }
        if (!S_ISREG(st.st_mode)) {
            close(raspFD);
            RBSetStoreError(error, RBAuthStoreErrorCorrupt, @"auth store: unsafe authorization file");
            return NO;
        }

        if (unlinkat(raspFD, RBAuthStoreFileName, 0) != 0 && errno != ENOENT) {
            close(raspFD);
            RBSetStoreError(error, RBAuthStoreErrorIO, @"auth store: authorization unlink failed");
            return NO;
        }
        (void)fsync(raspFD);
        close(raspFD);
        return YES;
    }
}

- (BOOL)clearCachedCookieError:(NSError * _Nullable * _Nullable)error {
    if (error != NULL) {
        *error = nil;
    }

    @synchronized(self) {
        RBAuthStoreErrorCode openCode = RBAuthStoreErrorIO;
        NSString *openMessage = nil;
        int cachesFD =
            RBOpenSecureDirectoryPath(_cachesPath.fileSystemRepresentation,
                                      &openCode, &openMessage);
        if (cachesFD < 0) {
            if (openCode == RBAuthStoreErrorNotFound) {
                return YES;
            }
            RBSetStoreError(error, openCode, openMessage);
            return NO;
        }

        struct stat cookieSt;
        if (fstatat(cachesFD, RBAuthStoreCookieName, &cookieSt,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            int err = errno;
            close(cachesFD);
            if (err == ENOENT) {
                return YES;
            }
            RBSetStoreError(error, RBAuthStoreErrorIO,
                            @"auth store: cache stat failed");
            return NO;
        }
        if (!S_ISREG(cookieSt.st_mode)) {
            close(cachesFD);
            RBSetStoreError(error, RBAuthStoreErrorCorrupt,
                            @"auth store: unsafe cache file");
            return NO;
        }

        if (unlinkat(cachesFD, RBAuthStoreCookieName, 0) != 0) {
            int err = errno;
            close(cachesFD);
            if (err == ENOENT) {
                return YES;
            }
            RBSetStoreError(error, RBAuthStoreErrorIO,
                            @"auth store: cache cleanup failed");
            return NO;
        }
        if (fsync(cachesFD) != 0) {
            close(cachesFD);
            RBSetStoreError(error, RBAuthStoreErrorIO,
                            @"auth store: cache directory sync failed");
            return NO;
        }
        close(cachesFD);
        return YES;
    }
}

@end
