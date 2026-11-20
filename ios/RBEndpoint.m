#import "RBEndpoint.h"

#import <CoreFoundation/CoreFoundation.h>
#import <errno.h>
#import <fcntl.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

NSString *const RBEndpointErrorDomain = @"org.raspberry.endpoint";

static const NSUInteger RBEndpointMaxJSONBytes = 64u * 1024u;
enum { RBEndpointMaxFileBytes = 4096u };

@interface RBEndpoint () {
    rb_config _config;
}

- (instancetype)initWithConfig:(const rb_config *)config;

@end

static NSError *RBMakeError(RBEndpointErrorCode code, NSString *message) {
    return [NSError errorWithDomain:RBEndpointErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

static BOOL RBIsJSONWhitespace(NSData *data) {
    const uint8_t *bytes = data.bytes;
    for (NSUInteger i = 0; i < data.length; i++) {
        switch (bytes[i]) {
            case ' ':
            case '\t':
            case '\n':
            case '\r':
                break;
            default:
                return NO;
        }
    }
    return YES;
}

static BOOL RBIsBoolean(NSNumber *number) {
    return CFGetTypeID((__bridge CFTypeRef)number) == CFBooleanGetTypeID();
}

static BOOL RBIsFloatingNumber(NSNumber *number) {
    const char *type = number.objCType;
    return type != NULL && (type[0] == 'f' || type[0] == 'd');
}

static BOOL RBExactVersionOne(id value) {
    if (![value isKindOfClass:[NSNumber class]]) {
        return NO;
    }
    NSNumber *number = (NSNumber *)value;
    return !RBIsBoolean(number) && !RBIsFloatingNumber(number) &&
           [number.stringValue isEqualToString:@"1"];
}

static BOOL RBPortValue(id value, int *outPort) {
    if (![value isKindOfClass:[NSNumber class]]) {
        return NO;
    }
    NSNumber *number = (NSNumber *)value;
    if (RBIsBoolean(number) || RBIsFloatingNumber(number)) {
        return NO;
    }
    NSString *digits = number.stringValue;
    if (digits.length == 0) {
        return NO;
    }
    int port = 0;
    for (NSUInteger i = 0; i < digits.length; i++) {
        unichar c = [digits characterAtIndex:i];
        if (c < '0' || c > '9') {
            return NO;
        }
        port = port * 10 + (int)(c - '0');
        if (port > 65535) {
            return NO;
        }
    }
    if (port < 1) {
        return NO;
    }
    *outPort = port;
    return YES;
}

static BOOL RBASCIIString(NSString *string, char *buffer, size_t capacity, NSUInteger maxLength) {
    if (string == nil || string.length == 0 || string.length > maxLength ||
        [string rangeOfString:@"\0"].location != NSNotFound || string.length + 1 > capacity) {
        return NO;
    }
    for (NSUInteger i = 0; i < string.length; i++) {
        unichar c = [string characterAtIndex:i];
        if (c > 0x7f) {
            return NO;
        }
        buffer[i] = (char)c;
    }
    buffer[string.length] = '\0';
    return YES;
}

static NSInteger RBPortIndex(NSString *key) {
    if ([key isEqualToString:@"80"]) {
        return 0;
    }
    if ([key isEqualToString:@"443"]) {
        return 1;
    }
    if ([key isEqualToString:@"10000"]) {
        return 2;
    }
    if ([key isEqualToString:@"10123"]) {
        return 3;
    }
    return NSNotFound;
}

@implementation RBEndpoint

+ (nullable instancetype)endpointWithJSONData:(nullable NSData *)data
                                      error:(NSError * _Nullable * _Nullable)error {
    if (error != NULL) {
        *error = nil;
    }
    if (data.length > RBEndpointMaxJSONBytes) {
        if (error != NULL) {
            *error = RBMakeError(RBEndpointErrorTooLarge, @"descriptor: too large");
        }
        return nil;
    }
    if (RBIsJSONWhitespace(data)) {
        if (error != NULL) {
            *error = RBMakeError(RBEndpointErrorEmpty, @"descriptor: empty");
        }
        return nil;
    }

    NSError *jsonError = nil;
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
    (void)jsonError;
    if (![object isKindOfClass:[NSDictionary class]]) {
        if (error != NULL) {
            *error = RBMakeError(RBEndpointErrorNotJSON, @"descriptor: not json");
        }
        return nil;
    }
    NSDictionary *top = (NSDictionary *)object;
    if (!RBExactVersionOne(top[@"v"])) {
        if (error != NULL) {
            *error = RBMakeError(RBEndpointErrorVersion, @"descriptor: v must be 1");
        }
        return nil;
    }

    id rawHost = top[@"host"];
    if (rawHost == nil) {
        if (error != NULL) {
            *error = RBMakeError(RBEndpointErrorHostRequired, @"descriptor: host required");
        }
        return nil;
    }
    if (![rawHost isKindOfClass:[NSString class]]) {
        if (error != NULL) {
            *error = RBMakeError(RBEndpointErrorHostInvalid, @"descriptor: host invalid");
        }
        return nil;
    }

    int ports[RB_PORT_N] = {80, 443, 10000, 10123};
    id rawPorts = top[@"ports"];
    if (rawPorts != nil) {
        if (![rawPorts isKindOfClass:[NSDictionary class]]) {
            if (error != NULL) {
                *error = RBMakeError(RBEndpointErrorPortsInvalid, @"descriptor: ports invalid");
            }
            return nil;
        }
        NSDictionary *portMap = (NSDictionary *)rawPorts;
        for (id key in portMap) {
            if (![key isKindOfClass:[NSString class]]) {
                if (error != NULL) {
                    *error = RBMakeError(RBEndpointErrorPortKeyNotAllowed, @"descriptor: port key not allowed");
                }
                return nil;
            }
            NSInteger index = RBPortIndex((NSString *)key);
            if (index == NSNotFound) {
                if (error != NULL) {
                    *error = RBMakeError(RBEndpointErrorPortKeyNotAllowed, @"descriptor: port key not allowed");
                }
                return nil;
            }
            int port = 0;
            if (!RBPortValue(portMap[key], &port)) {
                if (error != NULL) {
                    *error = RBMakeError(RBEndpointErrorPortOutOfRange, @"descriptor: port out of range");
                }
                return nil;
            }
            ports[index] = port;
        }
    }

    char rawHostBuffer[RB_HOST_MAX + 1];
    if (!RBASCIIString((NSString *)rawHost, rawHostBuffer, sizeof rawHostBuffer, RB_HOST_MAX)) {
        if (error != NULL) {
            *error = RBMakeError(RBEndpointErrorHostInvalid, @"descriptor: host invalid");
        }
        return nil;
    }

    rb_config config;
    if (!rb_validate(rawHostBuffer, ports, &config)) {
        if (error != NULL) {
            *error = RBMakeError(RBEndpointErrorHostInvalid, @"descriptor: host invalid");
        }
        return nil;
    }
    return [[self alloc] initWithConfig:&config];
}

+ (nullable instancetype)endpointFromFileURL:(nullable NSURL *)fileURL
                                       error:(NSError * _Nullable * _Nullable)error {
    if (error != NULL) {
        *error = nil;
    }
    if (fileURL == nil || !fileURL.isFileURL || fileURL.path.length == 0) {
        if (error != NULL) {
            *error = RBMakeError(RBEndpointErrorUnreadable, @"descriptor: file unreadable");
        }
        return nil;
    }

    const char *path = NULL;
    @try {
        path = fileURL.fileSystemRepresentation;
    } @catch (NSException *exception) {
        (void)exception;
        path = NULL;
    }
    if (path == NULL || path[0] == '\0') {
        if (error != NULL) {
            *error = RBMakeError(RBEndpointErrorUnreadable, @"descriptor: file unreadable");
        }
        return nil;
    }

    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (error != NULL) {
            *error = RBMakeError(RBEndpointErrorUnreadable, @"descriptor: file unreadable");
        }
        return nil;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        if (error != NULL) {
            *error = RBMakeError(RBEndpointErrorUnreadable, @"descriptor: file unreadable");
        }
        return nil;
    }

    uint8_t buffer[RBEndpointMaxFileBytes + 1u];
    size_t total = 0;
    while (total < sizeof(buffer)) {
        ssize_t n = read(fd, buffer + total, sizeof(buffer) - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            if (error != NULL) {
                *error = RBMakeError(RBEndpointErrorUnreadable, @"descriptor: file unreadable");
            }
            return nil;
        }
        if (n == 0) {
            break;
        }
        total += (size_t)n;
    }
    close(fd);

    if (total == 0) {
        if (error != NULL) {
            *error = RBMakeError(RBEndpointErrorEmpty, @"descriptor: empty");
        }
        return nil;
    }
    if (total > RBEndpointMaxFileBytes) {
        if (error != NULL) {
            *error = RBMakeError(RBEndpointErrorTooLarge, @"descriptor: too large");
        }
        return nil;
    }

    NSData *data = [NSData dataWithBytes:buffer length:total];
    return [self endpointWithJSONData:data error:error];
}

- (instancetype)initWithConfig:(const rb_config *)config {
    self = [super init];
    if (self != nil) {
        _config = *config;
        _host = [[NSString alloc] initWithUTF8String:_config.host];
        if (_config.ports[1] == 443) {
            _httpsOrigin = [NSString stringWithFormat:@"https://%@", _host];
        } else {
            _httpsOrigin = [NSString stringWithFormat:@"https://%@:%u", _host, _config.ports[1]];
        }
    }
    return self;
}

- (uint16_t)mappedPortForOriginalClientPort:(uint16_t)originalPort {
    switch (originalPort) {
        case 80:
            return _config.ports[0];
        case 443:
            return _config.ports[1];
        case 10000:
            return _config.ports[2];
        case 10123:
            return _config.ports[3];
        default:
            return originalPort;
    }
}

- (BOOL)redirectsHost:(NSString *)hostname {
    char input[RB_HOST_MAX + 2];
    if (!RBASCIIString(hostname, input, sizeof input, RB_HOST_MAX + 1)) {
        return NO;
    }
    return rb_redirect(input) != 0;
}

- (rb_config)copyOutRBConfig {
    return _config;
}

- (id)copyWithZone:(NSZone *)zone {
    (void)zone;
    return self;
}

@end
