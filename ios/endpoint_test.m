#import "RBEndpoint.h"

#import <CoreFoundation/CoreFoundation.h>
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

static RBEndpoint *Endpoint(NSString *json) {
    NSError *error = nil;
    RBEndpoint *endpoint = [RBEndpoint endpointWithJSONData:[json dataUsingEncoding:NSUTF8StringEncoding]
                                                       error:&error];
    if (endpoint == nil) {
        fprintf(stderr, "unexpected descriptor rejection: %s\n", error.localizedDescription.UTF8String);
        failures++;
    }
    return endpoint;
}

static void ExpectReject(NSString *json, RBEndpointErrorCode code, const char *label) {
    NSError *error = nil;
    RBEndpoint *endpoint = [RBEndpoint endpointWithJSONData:[json dataUsingEncoding:NSUTF8StringEncoding]
                                                       error:&error];
    CHECK(endpoint == nil, label);
    CHECK(error.domain == RBEndpointErrorDomain || [error.domain isEqualToString:RBEndpointErrorDomain], "error domain");
    CHECK(error.code == code, label);
    CHECK(error.localizedDescription.length > 0, "fixed error message");
    CHECK(![error.localizedDescription containsString:json], "error does not echo JSON");
}

static void TestDefaultsAndCase(void) {
    RBEndpoint *endpoint = Endpoint(@"{\"v\":1,\"host\":\"Example.Test\",\"note\":\"ignored\"}");
    if (endpoint == nil) {
        return;
    }
    CHECK([endpoint.host isEqualToString:@"example.test"], "canonical lowercase host");
    CHECK([endpoint.httpsOrigin isEqualToString:@"https://example.test"], "default HTTPS origin");
    CHECK([endpoint mappedPortForOriginalClientPort:80] == 80, "identity 80");
    CHECK([endpoint mappedPortForOriginalClientPort:443] == 443, "identity 443");
    CHECK([endpoint mappedPortForOriginalClientPort:10000] == 10000, "identity 10000");
    CHECK([endpoint mappedPortForOriginalClientPort:10123] == 10123, "identity 10123");
    CHECK([endpoint mappedPortForOriginalClientPort:1234] == 1234, "unknown port unchanged");
}

static void TestFullPortsAndRedirect(void) {
    RBEndpoint *endpoint = Endpoint(@"{\"v\":1,\"host\":\"Example.Test\",\"ports\":{\"80\":8080,\"443\":8443,\"10000\":20000,\"10123\":20123}}");
    if (endpoint == nil) {
        return;
    }
    CHECK([endpoint.host isEqualToString:@"example.test"], "full map host");
    CHECK([endpoint.httpsOrigin isEqualToString:@"https://example.test:8443"], "mapped HTTPS origin");
    CHECK([endpoint mappedPortForOriginalClientPort:80] == 8080, "mapped 80");
    CHECK([endpoint mappedPortForOriginalClientPort:443] == 8443, "mapped 443");
    CHECK([endpoint mappedPortForOriginalClientPort:10000] == 20000, "mapped 10000");
    CHECK([endpoint mappedPortForOriginalClientPort:10123] == 20123, "mapped 10123");
    CHECK([endpoint redirectsHost:@"FAPI.PLAY.NAVER.JP"], "shared redirect case-fold");
    CHECK([endpoint redirectsHost:@"ads.play.naver.jp"], "shared exact redirect");
    CHECK(![endpoint redirectsHost:@"example.test"], "endpoint host is not implicitly redirectable");
    CHECK(![endpoint redirectsHost:@"evilplay.naver.jp"], "shared suffix boundary");

    RBEndpoint *partial = Endpoint(@"{\"v\":1,\"host\":\"example.test\",\"ports\":{\"443\":8443}}");
    CHECK(partial != nil && [partial mappedPortForOriginalClientPort:80] == 80, "partial map default 80");
    CHECK(partial != nil && [partial mappedPortForOriginalClientPort:443] == 8443, "partial map 443");
    CHECK(partial != nil && [partial mappedPortForOriginalClientPort:10000] == 10000, "partial map default 10000");
    CHECK(partial != nil && [partial mappedPortForOriginalClientPort:10123] == 10123, "partial map default 10123");
}

static void TestHostValidation(void) {
    RBEndpoint *localhost = Endpoint(@"{\"v\":1,\"host\":\"localhost\"}");
    CHECK(localhost != nil && [localhost.host isEqualToString:@"localhost"], "localhost allowed");
    RBEndpoint *localdomain = Endpoint(@"{\"v\":1,\"host\":\"localhost.localdomain\"}");
    CHECK(localdomain != nil && [localdomain.host isEqualToString:@"localhost.localdomain"], "localhost domain allowed");
    RBEndpoint *ipv4 = Endpoint(@"{\"v\":1,\"host\":\"203.0.113.10\"}");
    CHECK(ipv4 != nil && [ipv4.host isEqualToString:@"203.0.113.10"], "strict IPv4 allowed");

    ExpectReject(@"{\"v\":1,\"host\":\"bad\\u0000.example\"}", RBEndpointErrorHostInvalid, "embedded NUL");
    ExpectReject(@"{\"v\":1,\"host\":\"caf\u00e9.example\"}", RBEndpointErrorHostInvalid, "Unicode host");
    ExpectReject(@"{\"v\":1,\"host\":\"198.18.0.1\"}", RBEndpointErrorHostInvalid, "routing marker");
    ExpectReject(@"{\"v\":1,\"host\":\"127.1\"}", RBEndpointErrorHostInvalid, "ambiguous numeric");
    ExpectReject(@"{\"v\":1,\"host\":\"0x7f000001\"}", RBEndpointErrorHostInvalid, "hex numeric");
    ExpectReject(@"{\"v\":1,\"host\":\"01.2.3.4\"}", RBEndpointErrorHostInvalid, "leading-zero IPv4");
}

static void TestJSONAndVersionValidation(void) {
    ExpectReject(@"", RBEndpointErrorEmpty, "empty");
    ExpectReject(@"   \n\t", RBEndpointErrorEmpty, "whitespace");
    ExpectReject([@"{\"v\":1,\"host\":\"example.test\"}" stringByPaddingToLength:65537 withString:@" " startingAtIndex:0],
                 RBEndpointErrorTooLarge, "oversized JSON");
    ExpectReject(@"{", RBEndpointErrorNotJSON, "malformed JSON");
    ExpectReject(@"{\"v\":1,\"host\":\"bad\nhost\"}", RBEndpointErrorNotJSON, "raw control in JSON string");
    ExpectReject(@"[]", RBEndpointErrorNotJSON, "non-object");
    ExpectReject(@"{\"v\":1,\"host\":\"example.test\"} trailing", RBEndpointErrorNotJSON, "trailing data");
    ExpectReject(@"{\"v\":true,\"host\":\"example.test\"}", RBEndpointErrorVersion, "boolean version");
    ExpectReject(@"{\"v\":null,\"host\":\"example.test\"}", RBEndpointErrorVersion, "null version");
    ExpectReject(@"{\"v\":1.0,\"host\":\"example.test\"}", RBEndpointErrorVersion, "fractional version");
    ExpectReject(@"{\"v\":1e0,\"host\":\"example.test\"}", RBEndpointErrorVersion, "scientific version");
    ExpectReject(@"{\"v\":\"1\",\"host\":\"example.test\"}", RBEndpointErrorVersion, "string version");
    ExpectReject(@"{\"v\":01,\"host\":\"example.test\"}", RBEndpointErrorNotJSON, "leading-zero version");
    ExpectReject(@"{\"v\":2,\"host\":\"example.test\"}", RBEndpointErrorVersion, "wrong version");
    ExpectReject(@"{\"v\":18446744073709551616,\"host\":\"example.test\"}", RBEndpointErrorVersion, "oversized version");
    ExpectReject(@"{\"host\":\"example.test\"}", RBEndpointErrorVersion, "missing version");
    ExpectReject(@"{\"v\":1}", RBEndpointErrorHostRequired, "missing host");
    ExpectReject(@"{\"v\":1,\"host\":null}", RBEndpointErrorHostInvalid, "null host");
    ExpectReject(@"{\"v\":1,\"host\":false}", RBEndpointErrorHostInvalid, "non-string host");
}

static void TestPortValidation(void) {
    ExpectReject(@"{\"v\":1,\"host\":\"example.test\",\"ports\":null}", RBEndpointErrorPortsInvalid, "null ports");
    ExpectReject(@"{\"v\":1,\"host\":\"example.test\",\"ports\":[]}", RBEndpointErrorPortsInvalid, "array ports");
    ExpectReject(@"{\"v\":1,\"host\":\"example.test\",\"ports\":{\"22\":22}}", RBEndpointErrorPortKeyNotAllowed, "unknown port");
    ExpectReject(@"{\"v\":1,\"host\":\"example.test\",\"ports\":{\"80\":true}}", RBEndpointErrorPortOutOfRange, "boolean port");
    ExpectReject(@"{\"v\":1,\"host\":\"example.test\",\"ports\":{\"80\":null}}", RBEndpointErrorPortOutOfRange, "null port");
    ExpectReject(@"{\"v\":1,\"host\":\"example.test\",\"ports\":{\"80\":1.5}}", RBEndpointErrorPortOutOfRange, "fractional port");
    ExpectReject(@"{\"v\":1,\"host\":\"example.test\",\"ports\":{\"80\":1e2}}", RBEndpointErrorPortOutOfRange, "scientific port");
    ExpectReject(@"{\"v\":1,\"host\":\"example.test\",\"ports\":{\"443\":0443}}", RBEndpointErrorNotJSON, "leading-zero port");
    ExpectReject(@"{\"v\":1,\"host\":\"example.test\",\"ports\":{\"80\":18446744073709551616}}",
                 RBEndpointErrorPortOutOfRange, "huge port");
    ExpectReject(@"{\"v\":1,\"host\":\"example.test\",\"ports\":{\"80\":0}}", RBEndpointErrorPortOutOfRange, "zero port");
    ExpectReject(@"{\"v\":1,\"host\":\"example.test\",\"ports\":{\"80\":65536}}", RBEndpointErrorPortOutOfRange, "oversized port");
    ExpectReject(@"{\"v\":1,\"host\":\"example.test\",\"ports\":{\"80\":\"80\"}}", RBEndpointErrorPortOutOfRange, "string port");

    RBEndpoint *maxPort = Endpoint(@"{\"v\":1,\"host\":\"example.test\",\"ports\":{\"443\":65535}}");
    CHECK(maxPort != nil && [maxPort mappedPortForOriginalClientPort:443] == 65535, "maximum port allowed");
}

static void TestImmutabilityAndConfigCopy(void) {
    NSMutableData *json = [[NSMutableData alloc] initWithData:[@"{\"v\":1,\"host\":\"Example.Test\",\"ports\":{\"443\":8443}}" dataUsingEncoding:NSUTF8StringEncoding]];
    NSError *error = nil;
    RBEndpoint *endpoint = [RBEndpoint endpointWithJSONData:json error:&error];
    CHECK(endpoint != nil, "mutable descriptor parses");
    if (endpoint == nil) {
        return;
    }
    memset(json.mutableBytes, 'x', json.length);
    CHECK([endpoint.host isEqualToString:@"example.test"], "source data mutation isolated");
    CHECK([endpoint.httpsOrigin isEqualToString:@"https://example.test:8443"], "origin immutable");
    CHECK(![endpoint respondsToSelector:NSSelectorFromString(@"setHost:")], "no host setter");
    CHECK(![endpoint respondsToSelector:NSSelectorFromString(@"setHttpsOrigin:")], "no origin setter");
    CHECK([[endpoint copy] isEqual:endpoint], "immutable copy");

    rb_config config = [endpoint copyOutRBConfig];
    CHECK(strcmp(config.host, "example.test") == 0, "C config host");
    CHECK(config.ports[1] == 8443, "C config mapped port");
    config.host[0] = 'x';
    config.ports[1] = 1;
    rb_config fresh = [endpoint copyOutRBConfig];
    CHECK(strcmp(fresh.host, "example.test") == 0, "C config independent host copy");
    CHECK(fresh.ports[1] == 8443, "C config independent ports copy");
}

static void TestErrorDoesNotEchoInput(void) {
    NSString *input = @"{\"v\":1,\"host\":\"bad host\",\"secret\":\"synthetic-private-value\"}";
    NSError *error = nil;
    RBEndpoint *endpoint = [RBEndpoint endpointWithJSONData:[input dataUsingEncoding:NSUTF8StringEncoding]
                                                       error:&error];
    CHECK(endpoint == nil, "invalid host rejected");
    CHECK(![error.localizedDescription containsString:@"bad host"], "host not echoed");
    CHECK(![error.localizedDescription containsString:@"synthetic-private-value"], "extra value not echoed");
}

static void TestOptionalInputsAndErrors(void) {
    NSError *error = nil;
    CHECK([RBEndpoint endpointWithJSONData:nil error:&error] == nil, "nil data rejected");
    CHECK(error.code == RBEndpointErrorEmpty, "nil data error");
    NSData *valid = [@"{\"v\":1,\"host\":\"example.test\"}" dataUsingEncoding:NSUTF8StringEncoding];
    CHECK([RBEndpoint endpointWithJSONData:valid error:NULL] != nil, "optional error on success");
    NSData *invalid = [@"{" dataUsingEncoding:NSUTF8StringEncoding];
    CHECK([RBEndpoint endpointWithJSONData:invalid error:NULL] == nil, "optional error on failure");
    CHECK([RBEndpoint endpointWithJSONData:valid error:&error] != nil && error == nil, "stale error cleared");
}

static void ExpectFileReject(NSURL *url, RBEndpointErrorCode code, const char *label) {
    NSError *error = nil;
    RBEndpoint *endpoint = [RBEndpoint endpointFromFileURL:url error:&error];
    CHECK(endpoint == nil, label);
    CHECK(error != nil && [error.domain isEqualToString:RBEndpointErrorDomain], "file error domain");
    CHECK(error.code == code, label);
    CHECK(error.localizedDescription.length > 0, "file error message non-empty");
    if (url != nil && url.lastPathComponent.length > 0) {
        CHECK(![error.localizedDescription containsString:url.lastPathComponent],
              "file error does not echo filename");
    }
}

static void TestFileLoader(void) {
    NSString *baseTmp = NSTemporaryDirectory();
    char resolvedRoot[PATH_MAX];
    const char *rawTmp = baseTmp.fileSystemRepresentation;
    CHECK(realpath(rawTmp, resolvedRoot) != NULL, "canonicalize temp root");
    if (realpath(rawTmp, resolvedRoot) == NULL) {
        return;
    }

    NSString *templateStr = [[NSString stringWithUTF8String:resolvedRoot]
        stringByAppendingPathComponent:@"rb-endpoint-test.XXXXXX"];
    char dirTemplate[PATH_MAX];
    snprintf(dirTemplate, sizeof(dirTemplate), "%s", templateStr.fileSystemRepresentation);
    char *dirPath = mkdtemp(dirTemplate);
    CHECK(dirPath != NULL, "create temp dir for file loader tests");
    if (dirPath == NULL) {
        return;
    }

    NSString *dir = [NSString stringWithUTF8String:dirPath];
    NSFileManager *fm = [NSFileManager defaultManager];

    NSString *validPath = [dir stringByAppendingPathComponent:@"valid-endpoint.json"];
    NSData *validData = [@"{\"v\":1,\"host\":\"File.Example.Test\",\"ports\":{\"443\":8443}}"
        dataUsingEncoding:NSUTF8StringEncoding];
    CHECK([validData writeToFile:validPath atomically:YES], "write valid endpoint file");
    NSURL *validURL = [NSURL fileURLWithPath:validPath];
    NSError *error = [NSError errorWithDomain:@"stale" code:1 userInfo:nil];
    RBEndpoint *loaded = [RBEndpoint endpointFromFileURL:validURL error:&error];
    CHECK(loaded != nil && error == nil, "load valid endpoint file and clear stale error");
    CHECK([loaded.host isEqualToString:@"file.example.test"], "file loader host");
    CHECK([loaded.httpsOrigin isEqualToString:@"https://file.example.test:8443"], "file loader origin");
    CHECK([loaded mappedPortForOriginalClientPort:443] == 8443, "file loader mapped 443");
    CHECK([RBEndpoint endpointFromFileURL:validURL error:NULL] != nil, "file loader optional error");

    NSString *exactLimitPath = [dir stringByAppendingPathComponent:@"exact-4096.json"];
    NSString *exactPadding = [@"" stringByPaddingToLength:4096u - validData.length
                                               withString:@" "
                                          startingAtIndex:0];
    NSMutableData *exactData = [NSMutableData dataWithData:validData];
    [exactData appendData:[exactPadding dataUsingEncoding:NSUTF8StringEncoding]];
    CHECK(exactData.length == 4096u, "exact 4096 byte fixture");
    CHECK([exactData writeToFile:exactLimitPath atomically:YES], "write exact 4096 byte file");
    RBEndpoint *exactLoaded = [RBEndpoint endpointFromFileURL:[NSURL fileURLWithPath:exactLimitPath]
                                                        error:&error];
    CHECK(exactLoaded != nil && error == nil, "exact 4096 byte endpoint file accepted");

    NSString *missingPath = [dir stringByAppendingPathComponent:@"missing-endpoint.json"];
    ExpectFileReject([NSURL fileURLWithPath:missingPath], RBEndpointErrorUnreadable, "missing file");

    NSString *symlinkPath = [dir stringByAppendingPathComponent:@"symlink-endpoint.json"];
    CHECK(symlink(validPath.fileSystemRepresentation, symlinkPath.fileSystemRepresentation) == 0,
          "create symlink fixture");
    ExpectFileReject([NSURL fileURLWithPath:symlinkPath], RBEndpointErrorUnreadable, "symlink refused");

    NSString *subDirPath = [dir stringByAppendingPathComponent:@"subdir.json"];
    CHECK([fm createDirectoryAtPath:subDirPath withIntermediateDirectories:NO attributes:nil error:NULL],
          "create subdir fixture");
    ExpectFileReject([NSURL fileURLWithPath:subDirPath isDirectory:YES],
                     RBEndpointErrorUnreadable, "directory refused");

    NSString *emptyPath = [dir stringByAppendingPathComponent:@"empty.json"];
    CHECK([[NSData data] writeToFile:emptyPath atomically:YES], "write empty file");
    ExpectFileReject([NSURL fileURLWithPath:emptyPath], RBEndpointErrorEmpty, "empty file");

    NSString *whitespacePath = [dir stringByAppendingPathComponent:@"whitespace.json"];
    CHECK([[@"  \n\t " dataUsingEncoding:NSUTF8StringEncoding] writeToFile:whitespacePath atomically:YES],
          "write whitespace file");
    ExpectFileReject([NSURL fileURLWithPath:whitespacePath], RBEndpointErrorEmpty, "whitespace file");

    NSString *oversizedPath = [dir stringByAppendingPathComponent:@"oversized.json"];
    NSMutableData *oversizedData = [NSMutableData dataWithData:exactData];
    [oversizedData appendBytes:" " length:1];
    CHECK(oversizedData.length == 4097u, "4097 byte fixture");
    CHECK([oversizedData writeToFile:oversizedPath atomically:YES], "write oversized file");
    ExpectFileReject([NSURL fileURLWithPath:oversizedPath], RBEndpointErrorTooLarge, "oversized file");

    NSString *badJSONPath = [dir stringByAppendingPathComponent:@"bad-json.json"];
    CHECK([[@"{\"v\":1," dataUsingEncoding:NSUTF8StringEncoding] writeToFile:badJSONPath atomically:YES],
          "write invalid JSON file");
    ExpectFileReject([NSURL fileURLWithPath:badJSONPath], RBEndpointErrorNotJSON, "invalid JSON file");

    ExpectFileReject(nil, RBEndpointErrorUnreadable, "nil file URL");
    ExpectFileReject([NSURL URLWithString:@"https://example.test/endpoint.json"],
                     RBEndpointErrorUnreadable, "non-file URL");
    CHECK([RBEndpoint endpointFromFileURL:[NSURL fileURLWithPath:missingPath] error:NULL] == nil,
          "file loader optional error on failure");

    [fm removeItemAtPath:dir error:NULL];
}

int main(void) {
    @autoreleasepool {
        TestDefaultsAndCase();
        TestFullPortsAndRedirect();
        TestHostValidation();
        TestJSONAndVersionValidation();
        TestPortValidation();
        TestImmutabilityAndConfigCopy();
        TestErrorDoesNotEchoInput();
        TestOptionalInputsAndErrors();
        TestFileLoader();
    }
    if (failures != 0) {
        fprintf(stderr, "%d endpoint test(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    puts("iOS endpoint core tests: ok");
    return EXIT_SUCCESS;
}
