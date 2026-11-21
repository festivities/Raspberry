#import "RBAuthStore.h"
#import "RBEndpoint.h"

#import <errno.h>
#import <fcntl.h>
#import <limits.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

static int failures = 0;

#define CHECK(condition, label)                                                                    \
    do {                                                                                            \
        if (!(condition)) {                                                                         \
            fprintf(stderr, "FAIL: %s\n", label);                                                   \
            failures++;                                                                             \
        }                                                                                           \
    } while (0)

static NSString *const RBTestCodeA = @"123e4567-e89b-12d3-a456-426614174000";
static NSString *const RBTestCodeB = @"999e4567-e89b-12d3-a456-426614174999";

static RBEndpoint *MakeEndpoint(NSString *host, uint16_t port443) {
    NSString *json = [NSString stringWithFormat:@"{\"v\":1,\"host\":\"%@\",\"ports\":{\"443\":%u}}",
                                                host, (unsigned)port443];
    NSError *error = nil;
    RBEndpoint *endpoint =
        [RBEndpoint endpointWithJSONData:[json dataUsingEncoding:NSUTF8StringEncoding] error:&error];
    CHECK(endpoint != nil && error == nil, "make endpoint fixture");
    return endpoint;
}

static NSString *CreateTempRoot(void) {
    NSString *baseTmp = NSTemporaryDirectory();
    char resolvedRoot[PATH_MAX];
    const char *rawTmp = baseTmp.fileSystemRepresentation;
    if (rawTmp == NULL || realpath(rawTmp, resolvedRoot) == NULL) {
        fprintf(stderr, "FAIL: canonicalize temp root\n");
        failures++;
        return nil;
    }
    NSString *templateStr = [[NSString stringWithUTF8String:resolvedRoot]
        stringByAppendingPathComponent:@"rb-auth-store-test.XXXXXX"];
    char dirTemplate[PATH_MAX];
    snprintf(dirTemplate, sizeof(dirTemplate), "%s", templateStr.fileSystemRepresentation);
    char *dirPath = mkdtemp(dirTemplate);
    if (dirPath == NULL) {
        fprintf(stderr, "FAIL: mkdtemp failed\n");
        failures++;
        return nil;
    }
    return [NSString stringWithUTF8String:dirPath];
}

static BOOL WriteRawFile(NSString *path, NSData *data, mode_t mode) {
    int fd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                  mode);
    if (fd < 0) {
        return NO;
    }
    const uint8_t *bytes = data.bytes;
    size_t remaining = data.length;
    size_t offset = 0;
    while (remaining > 0) {
        ssize_t n = write(fd, bytes + offset, remaining);
        if (n <= 0) {
            close(fd);
            return NO;
        }
        offset += (size_t)n;
        remaining -= (size_t)n;
    }
    if (fchmod(fd, mode) != 0) {
        close(fd);
        return NO;
    }
    close(fd);
    return YES;
}

static void CheckErrorClean(NSError *error,
                            RBAuthStoreErrorCode expectedCode,
                            NSString *sensitiveCode,
                            const char *label) {
    CHECK(error != nil, label);
    if (error == nil) {
        return;
    }
    CHECK([error.domain isEqualToString:RBAuthStoreErrorDomain], label);
    CHECK(error.code == expectedCode, label);
    CHECK(error.localizedDescription.length > 0, label);
    if (sensitiveCode.length > 0) {
        CHECK(![error.localizedDescription containsString:sensitiveCode],
              "error description never echoes uniqueCode");
    }
    CHECK(![error.localizedDescription containsString:@"cherry.example.org"],
          "error description never echoes host");
}

static void TestInitializerValidation(NSString *root) {
    NSString *basePath = [root stringByAppendingPathComponent:@"init-base"];
    NSString *cachesPath = [root stringByAppendingPathComponent:@"init-caches"];
    NSFileManager *fm = [NSFileManager defaultManager];
    CHECK([fm createDirectoryAtPath:basePath withIntermediateDirectories:NO attributes:nil error:NULL],
          "create init base");
    CHECK([fm createDirectoryAtPath:cachesPath withIntermediateDirectories:NO attributes:nil error:NULL],
          "create init caches");

    NSURL *baseURL = [NSURL fileURLWithPath:basePath isDirectory:YES];
    NSURL *cachesURL = [NSURL fileURLWithPath:cachesPath isDirectory:YES];
    NSURL *httpsURL = [NSURL URLWithString:@"https://cherry.example.org"];

    CHECK([[RBAuthStore alloc] initWithBaseDirectoryURL:nil cachesDirectoryURL:cachesURL] == nil,
          "nil baseDirectoryURL rejected");
    CHECK([[RBAuthStore alloc] initWithBaseDirectoryURL:baseURL cachesDirectoryURL:nil] == nil,
          "nil cachesDirectoryURL rejected");
    CHECK([[RBAuthStore alloc] initWithBaseDirectoryURL:httpsURL cachesDirectoryURL:cachesURL] == nil,
          "non-file baseDirectoryURL rejected");
    CHECK([[RBAuthStore alloc] initWithBaseDirectoryURL:baseURL cachesDirectoryURL:httpsURL] == nil,
          "non-file cachesDirectoryURL rejected");
    CHECK([[RBAuthStore alloc] initWithBaseDirectoryURL:baseURL cachesDirectoryURL:cachesURL] != nil,
          "valid directory URLs accepted");
}

static void TestRoundTripAndOriginIsolation(NSString *root) {
    NSString *basePath = [root stringByAppendingPathComponent:@"rt-base"];
    NSString *cachesPath = [root stringByAppendingPathComponent:@"rt-caches"];
    NSFileManager *fm = [NSFileManager defaultManager];
    CHECK([fm createDirectoryAtPath:basePath withIntermediateDirectories:NO attributes:nil error:NULL],
          "create rt base");
    CHECK([fm createDirectoryAtPath:cachesPath withIntermediateDirectories:NO attributes:nil error:NULL],
          "create rt caches");

    RBAuthStore *store =
        [[RBAuthStore alloc] initWithBaseDirectoryURL:[NSURL fileURLWithPath:basePath]
                                   cachesDirectoryURL:[NSURL fileURLWithPath:cachesPath]];
    RBEndpoint *endpoint8443 = MakeEndpoint(@"cherry.example.org", 8443);
    RBEndpoint *endpoint443 = MakeEndpoint(@"cherry.example.org", 443);
    RBEndpoint *otherHost = MakeEndpoint(@"other.example.org", 8443);

    NSError *error = nil;
    CHECK([store authorizedUniqueCodeForEndpoint:endpoint8443 error:&error] == nil,
          "initial read returns nil");
    CheckErrorClean(error, RBAuthStoreErrorNotFound, RBTestCodeA, "initial read reports NotFound");

    error = [NSError errorWithDomain:@"stale" code:99 userInfo:nil];
    CHECK([store commitUniqueCode:RBTestCodeA forEndpoint:endpoint8443 error:&error],
          "commit custom port succeeds");
    CHECK(error == nil, "commit clears stale error");

    NSString *raspDir = [basePath stringByAppendingPathComponent:@"raspberry"];
    struct stat dirSt;
    CHECK(lstat(raspDir.fileSystemRepresentation, &dirSt) == 0 && S_ISDIR(dirSt.st_mode) &&
              (dirSt.st_mode & 0777) == 0700,
          "raspberry subdir created with mode 0700");

    NSString *authPath = [raspDir stringByAppendingPathComponent:@"auth.json"];
    struct stat fileSt;
    CHECK(lstat(authPath.fileSystemRepresentation, &fileSt) == 0 && S_ISREG(fileSt.st_mode) &&
              (fileSt.st_mode & 0777) == 0600,
          "auth.json created with mode 0600");

    NSData *rawJSON = [NSData dataWithContentsOfFile:authPath];
    CHECK(rawJSON != nil && rawJSON.length <= 1024, "auth.json size <= 1024");
    id parsed = [NSJSONSerialization JSONObjectWithData:rawJSON options:0 error:NULL];
    CHECK([parsed isKindOfClass:[NSDictionary class]], "stored auth.json is dictionary");
    NSDictionary *dict = (NSDictionary *)parsed;
    CHECK(dict.count == 3 && [dict[@"v"] isEqual:@1] &&
              [dict[@"origin"] isEqualToString:@"https://cherry.example.org:8443"] &&
              [dict[@"uniqueCode"] isEqualToString:RBTestCodeA],
          "stored JSON matches strict schema");

    error = [NSError errorWithDomain:@"stale" code:99 userInfo:nil];
    NSString *loaded = [store authorizedUniqueCodeForEndpoint:endpoint8443 error:&error];
    CHECK([loaded isEqualToString:RBTestCodeA] && error == nil,
          "round-trip read returns matching uniqueCode and clears stale error");

    error = nil;
    CHECK([store authorizedUniqueCodeForEndpoint:endpoint443 error:&error] == nil,
          "different port rejected");
    CheckErrorClean(error, RBAuthStoreErrorOriginMismatch, RBTestCodeA,
                    "different port gives OriginMismatch");

    error = nil;
    CHECK([store authorizedUniqueCodeForEndpoint:otherHost error:&error] == nil,
          "different host rejected");
    CheckErrorClean(error, RBAuthStoreErrorOriginMismatch, RBTestCodeA,
                    "different host gives OriginMismatch");

    error = nil;
    CHECK([store authorizedUniqueCodeForEndpoint:nil error:&error] == nil,
          "nil endpoint rejected on read");
    CheckErrorClean(error, RBAuthStoreErrorInvalidInput, RBTestCodeA,
                    "nil endpoint gives InvalidInput");
}

static void TestCacheCookieCleanupAndSymlinkRefusal(NSString *root) {
    NSString *basePath = [root stringByAppendingPathComponent:@"cookie-base"];
    NSString *cachesPath = [root stringByAppendingPathComponent:@"cookie-caches"];
    NSFileManager *fm = [NSFileManager defaultManager];
    CHECK([fm createDirectoryAtPath:basePath withIntermediateDirectories:NO attributes:nil error:NULL],
          "create cookie base");
    CHECK([fm createDirectoryAtPath:cachesPath withIntermediateDirectories:NO attributes:nil error:NULL],
          "create cookie caches");

    RBAuthStore *store =
        [[RBAuthStore alloc] initWithBaseDirectoryURL:[NSURL fileURLWithPath:basePath]
                                   cachesDirectoryURL:[NSURL fileURLWithPath:cachesPath]];
    RBEndpoint *endpoint = MakeEndpoint(@"cherry.example.org", 8443);

    NSString *cookiePath = [cachesPath stringByAppendingPathComponent:@"avcookie.na"];
    NSString *siblingPath = [cachesPath stringByAppendingPathComponent:@"keep-sibling.dat"];
    NSData *siblingBytes = [@"sibling-cache-bytes" dataUsingEncoding:NSUTF8StringEncoding];
    CHECK(WriteRawFile(cookiePath, [@"old-cookie" dataUsingEncoding:NSUTF8StringEncoding], 0600),
          "create avcookie.na fixture");
    CHECK(WriteRawFile(siblingPath, siblingBytes, 0600), "create sibling cache fixture");

    NSError *error = nil;
    CHECK([store commitUniqueCode:RBTestCodeA forEndpoint:endpoint error:&error] && error == nil,
          "commit with existing avcookie.na succeeds");
    CHECK(![fm fileExistsAtPath:cookiePath], "regular avcookie.na removed");
    CHECK([[NSData dataWithContentsOfFile:siblingPath] isEqualToData:siblingBytes],
          "sibling cache file untouched");

    error = nil;
    CHECK([store commitUniqueCode:RBTestCodeB forEndpoint:endpoint error:&error] && error == nil,
          "commit when avcookie.na absent succeeds");
    CHECK([[store authorizedUniqueCodeForEndpoint:endpoint error:NULL] isEqualToString:RBTestCodeB],
          "second commit updates uniqueCode");

    CHECK(WriteRawFile(cookiePath, [@"runtime-cookie" dataUsingEncoding:NSUTF8StringEncoding],
                       0600),
          "create cookie for explicit cleanup");
    error = [NSError errorWithDomain:@"stale" code:99 userInfo:nil];
    CHECK([store clearCachedCookieError:&error] && error == nil,
          "explicit cached-cookie cleanup succeeds and clears stale error");
    CHECK(![fm fileExistsAtPath:cookiePath],
          "explicit cached-cookie cleanup removes avcookie.na");
    CHECK([[NSData dataWithContentsOfFile:siblingPath] isEqualToData:siblingBytes],
          "explicit cached-cookie cleanup leaves sibling untouched");
    error = nil;
    CHECK([store clearCachedCookieError:&error] && error == nil,
          "explicit cached-cookie cleanup is idempotent");

    NSString *targetPath = [root stringByAppendingPathComponent:@"do-not-delete.dat"];
    NSData *targetBytes = [@"protected-target" dataUsingEncoding:NSUTF8StringEncoding];
    CHECK(WriteRawFile(targetPath, targetBytes, 0600), "create symlink target");
    CHECK(symlink(targetPath.fileSystemRepresentation, cookiePath.fileSystemRepresentation) == 0,
          "create symlink avcookie.na");

    error = nil;
    CHECK(![store clearCachedCookieError:&error],
          "explicit cached-cookie cleanup refuses symlink avcookie.na");
    CheckErrorClean(error, RBAuthStoreErrorCorrupt, RBTestCodeA,
                    "explicit symlink avcookie.na cleanup reports Corrupt");
    struct stat explicitSymSt;
    CHECK(lstat(cookiePath.fileSystemRepresentation, &explicitSymSt) == 0 &&
              S_ISLNK(explicitSymSt.st_mode),
          "explicit cached-cookie cleanup preserves symlink");
    CHECK([[NSData dataWithContentsOfFile:targetPath] isEqualToData:targetBytes],
          "explicit cached-cookie cleanup preserves symlink target");

    error = nil;
    CHECK(![store commitUniqueCode:RBTestCodeA forEndpoint:endpoint error:&error],
          "commit refuses symlink avcookie.na");
    CheckErrorClean(error, RBAuthStoreErrorCorrupt, RBTestCodeA,
                    "symlink avcookie.na reports Corrupt");
    struct stat symSt;
    CHECK(lstat(cookiePath.fileSystemRepresentation, &symSt) == 0 && S_ISLNK(symSt.st_mode),
          "symlink avcookie.na not deleted");
    CHECK([[NSData dataWithContentsOfFile:targetPath] isEqualToData:targetBytes],
          "symlink target untouched");
    CHECK([[store authorizedUniqueCodeForEndpoint:endpoint error:NULL] isEqualToString:RBTestCodeB],
          "failed commit on symlink avcookie.na preserves prior auth.json");
}

static void TestCorruptionPermissionsAndSymlinks(NSString *root) {
    NSFileManager *fm = [NSFileManager defaultManager];
    RBEndpoint *endpoint = MakeEndpoint(@"cherry.example.org", 8443);

    // 1. Symlink auth.json, non-0600 auth.json, corrupt JSON, invalid UUID, oversized (>1024), 1024 exact.
    NSString *basePath = [root stringByAppendingPathComponent:@"corrupt-base"];
    NSString *cachesPath = [root stringByAppendingPathComponent:@"corrupt-caches"];
    CHECK([fm createDirectoryAtPath:basePath withIntermediateDirectories:NO attributes:nil error:NULL],
          "create corrupt base");
    CHECK([fm createDirectoryAtPath:cachesPath withIntermediateDirectories:NO attributes:nil error:NULL],
          "create corrupt caches");
    RBAuthStore *store =
        [[RBAuthStore alloc] initWithBaseDirectoryURL:[NSURL fileURLWithPath:basePath]
                                   cachesDirectoryURL:[NSURL fileURLWithPath:cachesPath]];
    CHECK([store commitUniqueCode:RBTestCodeA forEndpoint:endpoint error:NULL], "seed corrupt store");

    NSString *authPath = [[basePath stringByAppendingPathComponent:@"raspberry"]
        stringByAppendingPathComponent:@"auth.json"];

    // Non-0600 permissions (0644)
    CHECK(chmod(authPath.fileSystemRepresentation, 0644) == 0, "chmod auth.json 0644");
    NSError *error = nil;
    CHECK([store authorizedUniqueCodeForEndpoint:endpoint error:&error] == nil,
          "0644 auth.json refused");
    CheckErrorClean(error, RBAuthStoreErrorCorrupt, RBTestCodeA, "0644 reports Corrupt");
    CHECK(chmod(authPath.fileSystemRepresentation, 0600) == 0, "restore 0600");

    // Exact 1024 bytes accepted, 1025 bytes refused
    NSString *validJSON = [NSString stringWithFormat:@"{\"v\":1,\"origin\":\"https://cherry.example.org:8443\",\"uniqueCode\":\"%@\"}",
                                                     RBTestCodeA];
    NSMutableData *exact1024 = [NSMutableData dataWithData:[validJSON dataUsingEncoding:NSUTF8StringEncoding]];
    while (exact1024.length < 1024) {
        [exact1024 appendBytes:" " length:1];
    }
    CHECK(WriteRawFile(authPath, exact1024, 0600), "write 1024-byte auth.json");
    error = nil;
    CHECK([[store authorizedUniqueCodeForEndpoint:endpoint error:&error] isEqualToString:RBTestCodeA] &&
              error == nil,
          "1024-byte auth.json accepted");

    NSMutableData *over1024 = [NSMutableData dataWithData:exact1024];
    [over1024 appendBytes:" " length:1];
    CHECK(WriteRawFile(authPath, over1024, 0600), "write 1025-byte auth.json");
    error = nil;
    CHECK([store authorizedUniqueCodeForEndpoint:endpoint error:&error] == nil,
          "1025-byte auth.json refused");
    CheckErrorClean(error, RBAuthStoreErrorCorrupt, RBTestCodeA, "oversized reports Corrupt");

    // Corrupt JSON, bad version, extra key, invalid origin, uppercase/invalid UUID
    NSArray<NSString *> *badPayloads = @[
        @"{",
        @"[]",
        @"{\"v\":2,\"origin\":\"https://cherry.example.org:8443\",\"uniqueCode\":\"123e4567-e89b-12d3-a456-426614174000\"}",
        @"{\"v\":\"1\",\"origin\":\"https://cherry.example.org:8443\",\"uniqueCode\":\"123e4567-e89b-12d3-a456-426614174000\"}",
        @"{\"v\":true,\"origin\":\"https://cherry.example.org:8443\",\"uniqueCode\":\"123e4567-e89b-12d3-a456-426614174000\"}",
        @"{\"v\":1,\"origin\":\"https://cherry.example.org:8443\",\"uniqueCode\":\"123e4567-e89b-12d3-a456-426614174000\",\"extra\":1}",
        @"{\"v\":1,\"origin\":\"http://cherry.example.org:8443\",\"uniqueCode\":\"123e4567-e89b-12d3-a456-426614174000\"}",
        @"{\"v\":1,\"origin\":\"https://cherry.example.org:8443/path\",\"uniqueCode\":\"123e4567-e89b-12d3-a456-426614174000\"}",
        @"{\"v\":1,\"origin\":\"https://cherry.example.org:8443?q=1\",\"uniqueCode\":\"123e4567-e89b-12d3-a456-426614174000\"}",
        @"{\"v\":1,\"origin\":\"https://cherry.example.org:8443\",\"uniqueCode\":\"123E4567-E89B-12D3-A456-426614174000\"}",
        @"{\"v\":1,\"origin\":\"https://cherry.example.org:8443\",\"uniqueCode\":\"not-a-uuid\"}",
    ];
    for (NSString *payload in badPayloads) {
        CHECK(WriteRawFile(authPath, [payload dataUsingEncoding:NSUTF8StringEncoding], 0600),
              "write bad auth.json fixture");
        error = nil;
        CHECK([store authorizedUniqueCodeForEndpoint:endpoint error:&error] == nil,
              "bad payload refused");
        CheckErrorClean(error, RBAuthStoreErrorCorrupt, RBTestCodeA, "bad payload reports Corrupt");
    }

    // Symlink auth.json refused
    NSString *realAuth = [root stringByAppendingPathComponent:@"real-auth.json"];
    CHECK(WriteRawFile(realAuth, [validJSON dataUsingEncoding:NSUTF8StringEncoding], 0600),
          "write real-auth target");
    unlink(authPath.fileSystemRepresentation);
    CHECK(symlink(realAuth.fileSystemRepresentation, authPath.fileSystemRepresentation) == 0,
          "create symlink auth.json");
    error = nil;
    CHECK([store authorizedUniqueCodeForEndpoint:endpoint error:&error] == nil,
          "symlink auth.json refused on read");
    CheckErrorClean(error, RBAuthStoreErrorCorrupt, RBTestCodeA, "symlink auth.json reports Corrupt");
    error = nil;
    CHECK(![store clearAuthorizationError:&error], "clear refuses symlink auth.json");
    CheckErrorClean(error, RBAuthStoreErrorCorrupt, RBTestCodeA, "clear symlink reports Corrupt");

    // 2. Symlink raspberry dir and group-writable raspberry dir refused
    NSString *symBase = [root stringByAppendingPathComponent:@"sym-dir-base"];
    NSString *symCaches = [root stringByAppendingPathComponent:@"sym-dir-caches"];
    NSString *realRasp = [root stringByAppendingPathComponent:@"real-rasp"];
    CHECK([fm createDirectoryAtPath:symBase withIntermediateDirectories:NO attributes:nil error:NULL],
          "create sym-dir-base");
    CHECK([fm createDirectoryAtPath:symCaches withIntermediateDirectories:NO attributes:nil error:NULL],
          "create sym-dir-caches");
    CHECK([fm createDirectoryAtPath:realRasp withIntermediateDirectories:NO attributes:nil error:NULL],
          "create real-rasp");
    chmod(realRasp.fileSystemRepresentation, 0700);
    CHECK(WriteRawFile([realRasp stringByAppendingPathComponent:@"auth.json"],
                       [validJSON dataUsingEncoding:NSUTF8StringEncoding], 0600),
          "seed real-rasp/auth.json");
    NSString *symRasp = [symBase stringByAppendingPathComponent:@"raspberry"];
    CHECK(symlink(realRasp.fileSystemRepresentation, symRasp.fileSystemRepresentation) == 0,
          "create symlink raspberry dir");

    RBAuthStore *symStore =
        [[RBAuthStore alloc] initWithBaseDirectoryURL:[NSURL fileURLWithPath:symBase]
                                   cachesDirectoryURL:[NSURL fileURLWithPath:symCaches]];
    error = nil;
    CHECK([symStore authorizedUniqueCodeForEndpoint:endpoint error:&error] == nil,
          "symlink raspberry dir refused on read");
    CheckErrorClean(error, RBAuthStoreErrorCorrupt, RBTestCodeA,
                    "symlink raspberry read reports Corrupt");
    error = nil;
    CHECK(![symStore commitUniqueCode:RBTestCodeA forEndpoint:endpoint error:&error],
          "symlink raspberry dir refused on commit");
    CheckErrorClean(error, RBAuthStoreErrorCorrupt, RBTestCodeA,
                    "symlink raspberry commit reports Corrupt");

    // Group-writable raspberry dir refused
    unlink(symRasp.fileSystemRepresentation);
    CHECK(mkdir(symRasp.fileSystemRepresentation, 0700) == 0, "create real raspberry dir");
    CHECK(chmod(symRasp.fileSystemRepresentation, 0770) == 0, "chmod raspberry 0770");
    error = nil;
    CHECK(![symStore commitUniqueCode:RBTestCodeA forEndpoint:endpoint error:&error],
          "group-writable raspberry dir refused on commit");
    CheckErrorClean(error, RBAuthStoreErrorCorrupt, RBTestCodeA,
                    "group-writable raspberry commit reports Corrupt");

    // Symlink baseDirectoryURL with trailing slash still refused
    NSString *symBaseLink = [root stringByAppendingPathComponent:@"sym-base-link"];
    CHECK(symlink(basePath.fileSystemRepresentation, symBaseLink.fileSystemRepresentation) == 0,
          "create symlink base dir");
    RBAuthStore *symBaseStore =
        [[RBAuthStore alloc] initWithBaseDirectoryURL:[NSURL fileURLWithPath:symBaseLink isDirectory:YES]
                                   cachesDirectoryURL:[NSURL fileURLWithPath:symCaches]];
    error = nil;
    CHECK(![symBaseStore commitUniqueCode:RBTestCodeA forEndpoint:endpoint error:&error],
          "symlink base dir with trailing slash refused");
    CheckErrorClean(error, RBAuthStoreErrorCorrupt, RBTestCodeA,
                    "symlink base dir reports Corrupt");
}

static void TestInvalidCommitPreservesOldAndClearIsIdempotent(NSString *root) {
    NSString *basePath = [root stringByAppendingPathComponent:@"clear-base"];
    NSString *cachesPath = [root stringByAppendingPathComponent:@"clear-caches"];
    NSFileManager *fm = [NSFileManager defaultManager];
    CHECK([fm createDirectoryAtPath:basePath withIntermediateDirectories:NO attributes:nil error:NULL],
          "create clear base");
    CHECK([fm createDirectoryAtPath:cachesPath withIntermediateDirectories:NO attributes:nil error:NULL],
          "create clear caches");

    RBAuthStore *store =
        [[RBAuthStore alloc] initWithBaseDirectoryURL:[NSURL fileURLWithPath:basePath]
                                   cachesDirectoryURL:[NSURL fileURLWithPath:cachesPath]];
    RBEndpoint *endpoint = MakeEndpoint(@"cherry.example.org", 8443);

    CHECK([store commitUniqueCode:RBTestCodeA forEndpoint:endpoint error:NULL],
          "seed initial auth.json");

    NSString *cookiePath = [cachesPath stringByAppendingPathComponent:@"avcookie.na"];
    NSData *cookieBytes = [@"preserve-cookie" dataUsingEncoding:NSUTF8StringEncoding];
    CHECK(WriteRawFile(cookiePath, cookieBytes, 0600), "seed avcookie.na after initial commit");

    NSArray<NSString *> *badCodes = @[
        @"123E4567-E89B-12D3-A456-426614174000",
        @"123e4567-e89b-12d3-a456-42661417400",
        @"123e4567-e89b-12d3-a456-4266141740000",
        @"123e4567_e89b_12d3_a456_426614174000",
        @"",
    ];
    for (NSString *badCode in badCodes) {
        NSError *error = nil;
        CHECK(![store commitUniqueCode:badCode forEndpoint:endpoint error:&error],
              "invalid uniqueCode rejected");
        CheckErrorClean(error, RBAuthStoreErrorInvalidInput, badCode,
                        "invalid uniqueCode reports InvalidInput without echoing code");
    }
    NSError *error = nil;
    CHECK(![store commitUniqueCode:nil forEndpoint:endpoint error:&error], "nil uniqueCode rejected");
    CheckErrorClean(error, RBAuthStoreErrorInvalidInput, nil, "nil uniqueCode reports InvalidInput");
    error = nil;
    CHECK(![store commitUniqueCode:RBTestCodeB forEndpoint:nil error:&error], "nil endpoint rejected");
    CheckErrorClean(error, RBAuthStoreErrorInvalidInput, RBTestCodeB,
                    "nil endpoint reports InvalidInput without echoing uniqueCode");

    CHECK([[store authorizedUniqueCodeForEndpoint:endpoint error:NULL] isEqualToString:RBTestCodeA],
          "invalid commit preserves previous auth.json");
    CHECK([[NSData dataWithContentsOfFile:cookiePath] isEqualToData:cookieBytes],
          "invalid commit preserves avcookie.na");

    NSString *siblingInRasp = [[basePath stringByAppendingPathComponent:@"raspberry"]
        stringByAppendingPathComponent:@"endpoint.json"];
    NSData *siblingBytes = [@"{\"v\":1,\"host\":\"cherry.example.org\"}"
        dataUsingEncoding:NSUTF8StringEncoding];
    CHECK(WriteRawFile(siblingInRasp, siblingBytes, 0600), "create sibling file in raspberry");

    error = [NSError errorWithDomain:@"stale" code:1 userInfo:nil];
    CHECK([store clearAuthorizationError:&error] && error == nil,
          "clear removes auth.json and clears stale error");
    CHECK(![fm fileExistsAtPath:[[basePath stringByAppendingPathComponent:@"raspberry"]
                                    stringByAppendingPathComponent:@"auth.json"]],
          "auth.json removed by clear");
    CHECK([[NSData dataWithContentsOfFile:cookiePath] isEqualToData:cookieBytes],
          "clear does not touch avcookie.na");
    CHECK([[NSData dataWithContentsOfFile:siblingInRasp] isEqualToData:siblingBytes],
          "clear does not touch sibling files in raspberry");

    error = nil;
    CHECK([store clearAuthorizationError:&error] && error == nil,
          "second clear is idempotent");
    error = nil;
    CHECK([store authorizedUniqueCodeForEndpoint:endpoint error:&error] == nil,
          "read after clear returns nil");
    CheckErrorClean(error, RBAuthStoreErrorNotFound, RBTestCodeA,
                    "read after clear reports NotFound");
}

int main(void) {
    @autoreleasepool {
        NSString *root = CreateTempRoot();
        if (root != nil) {
            TestInitializerValidation(root);
            TestRoundTripAndOriginIsolation(root);
            TestCacheCookieCleanupAndSymlinkRefusal(root);
            TestCorruptionPermissionsAndSymlinks(root);
            TestInvalidCommitPreservesOldAndClearIsIdempotent(root);
            [[NSFileManager defaultManager] removeItemAtPath:root error:NULL];
        }
    }
    if (failures != 0) {
        fprintf(stderr, "%d auth store test(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    puts("iOS auth store tests: ok");
    return EXIT_SUCCESS;
}
