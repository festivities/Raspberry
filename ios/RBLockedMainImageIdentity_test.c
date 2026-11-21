#include "RBLockedMainImageIdentity.h"

#include <stdio.h>
#include <string.h>

#define TEST_COMMAND_CAPACITY 128u

typedef struct {
    struct mach_header_64 header;
    uint8_t commands[TEST_COMMAND_CAPACITY];
} SyntheticImage;

static const uint8_t kExpectedLockedUUID[16] = {
    0x07, 0xfd, 0x11, 0x97, 0x4e, 0xd4, 0x36, 0xc1,
    0x94, 0x81, 0x45, 0xc6, 0xee, 0x10, 0x9e, 0xda,
};

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "RBLockedMainImageIdentity_test:%d: %s\n", \
            __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static void initialize_image(SyntheticImage *image) {
    memset(image, 0, sizeof(*image));
    image->header.magic = MH_MAGIC_64;
    image->header.cputype = CPU_TYPE_ARM64;
    image->header.filetype = MH_EXECUTE;
}

static int append_command(SyntheticImage *image, const void *command,
    size_t size) {
    if (image == NULL || command == NULL ||
        size < sizeof(struct load_command) ||
        size > sizeof(image->commands) - image->header.sizeofcmds ||
        size > UINT32_MAX - image->header.sizeofcmds) {
        return 0;
    }
    memcpy(image->commands + image->header.sizeofcmds, command, size);
    image->header.sizeofcmds += (uint32_t)size;
    image->header.ncmds++;
    return 1;
}

static struct uuid_command locked_uuid_command(void) {
    struct uuid_command command = {0};
    command.cmd = LC_UUID;
    command.cmdsize = sizeof(command);
    memcpy(command.uuid, kExpectedLockedUUID, sizeof(kExpectedLockedUUID));
    return command;
}

static int test_locked_uuid_accepts_nonempty_changed_bundle_id(void) {
    SyntheticImage image;
    initialize_image(&image);
    struct uuid_command command = locked_uuid_command();
    CHECK(append_command(&image, &command, sizeof(command)));
    CHECK(memcmp(rb_locked_main_image_uuid, kExpectedLockedUUID,
                 sizeof(kExpectedLockedUUID)) == 0);
    CHECK(rb_locked_main_image_identity_matches(
        "org.example.repackaged", &image.header));
    return 0;
}

static int test_empty_bundle_id_is_rejected(void) {
    SyntheticImage image;
    initialize_image(&image);
    struct uuid_command command = locked_uuid_command();
    CHECK(append_command(&image, &command, sizeof(command)));
    CHECK(!rb_locked_main_image_identity_matches("", &image.header));
    CHECK(!rb_locked_main_image_identity_matches(NULL, &image.header));
    return 0;
}

static int test_malformed_uuid_command_is_rejected(void) {
    SyntheticImage image;
    initialize_image(&image);
    struct uuid_command command = locked_uuid_command();
    command.cmdsize -= sizeof(uint32_t);
    CHECK(append_command(&image, &command, command.cmdsize));
    CHECK(!rb_locked_main_image_identity_matches(
        "org.example.repackaged", &image.header));
    return 0;
}

static int test_missing_uuid_is_rejected(void) {
    SyntheticImage image;
    initialize_image(&image);
    struct build_version_command command = {0};
    command.cmd = LC_BUILD_VERSION;
    command.cmdsize = sizeof(command);
    command.platform = PLATFORM_IOS;
    command.minos = 0x000f0000u;
    command.sdk = 0x00100000u;
    CHECK(append_command(&image, &command, sizeof(command)));
    CHECK(!rb_locked_main_image_identity_matches(
        "org.example.repackaged", &image.header));
    return 0;
}

static int test_duplicate_uuid_is_rejected(void) {
    SyntheticImage image;
    initialize_image(&image);
    struct uuid_command command = locked_uuid_command();
    CHECK(append_command(&image, &command, sizeof(command)));
    CHECK(append_command(&image, &command, sizeof(command)));
    CHECK(!rb_locked_main_image_identity_matches(
        "org.example.repackaged", &image.header));
    return 0;
}

static int test_wrong_uuid_is_rejected(void) {
    SyntheticImage image;
    initialize_image(&image);
    struct uuid_command command = locked_uuid_command();
    command.uuid[0] ^= 0x80u;
    CHECK(append_command(&image, &command, sizeof(command)));
    CHECK(!rb_locked_main_image_identity_matches(
        "org.example.repackaged", &image.header));
    return 0;
}

static int test_command_bounds_are_rejected(void) {
    SyntheticImage image;
    initialize_image(&image);
    struct uuid_command command = locked_uuid_command();
    CHECK(append_command(&image, &command, sizeof(command)));
    image.header.sizeofcmds--;
    CHECK(!rb_locked_main_image_identity_matches(
        "org.example.repackaged", &image.header));
    return 0;
}

int main(void) {
    if (test_locked_uuid_accepts_nonempty_changed_bundle_id() != 0 ||
        test_empty_bundle_id_is_rejected() != 0 ||
        test_malformed_uuid_command_is_rejected() != 0 ||
        test_missing_uuid_is_rejected() != 0 ||
        test_duplicate_uuid_is_rejected() != 0 ||
        test_wrong_uuid_is_rejected() != 0 ||
        test_command_bounds_are_rejected() != 0) {
        return 1;
    }
    puts("RBLockedMainImageIdentity_test: all identity cases passed");
    return 0;
}
