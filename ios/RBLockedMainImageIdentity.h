#ifndef RB_LOCKED_MAIN_IMAGE_IDENTITY_H
#define RB_LOCKED_MAIN_IMAGE_IDENTITY_H

#include <mach-o/loader.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define RB_LOCKED_MAIN_IMAGE_MAX_COMMANDS 4096u
#define RB_LOCKED_MAIN_IMAGE_MAX_COMMAND_BYTES (1024u * 1024u)

static const uint8_t rb_locked_main_image_uuid[16] = {
    0x07, 0xfd, 0x11, 0x97, 0x4e, 0xd4, 0x36, 0xc1,
    0x94, 0x81, 0x45, 0xc6, 0xee, 0x10, 0x9e, 0xda,
};

/*
 * Match the locked executable by its Mach-O UUID, not its mutable bundle ID.
 * The bundle identifier is still required to be present and nonempty.
 */
static inline bool rb_locked_main_image_identity_matches(
    const char *bundle_identifier,
    const struct mach_header_64 *header) {
    if (bundle_identifier == NULL || bundle_identifier[0] == '\0' ||
        header == NULL || header->magic != MH_MAGIC_64 ||
        header->filetype != MH_EXECUTE || header->cputype != CPU_TYPE_ARM64 ||
        header->ncmds == 0 ||
        header->ncmds > RB_LOCKED_MAIN_IMAGE_MAX_COMMANDS ||
        header->sizeofcmds == 0 ||
        header->sizeofcmds > RB_LOCKED_MAIN_IMAGE_MAX_COMMAND_BYTES) {
        return false;
    }

    const uint8_t *cursor = (const uint8_t *)(header + 1);
    size_t remaining = header->sizeofcmds;
    bool found_uuid = false;
    for (uint32_t index = 0; index < header->ncmds; index++) {
        if (remaining < sizeof(struct load_command)) {
            return false;
        }

        struct load_command command;
        memcpy(&command, cursor, sizeof(command));
        if (command.cmdsize < sizeof(struct load_command) ||
            command.cmdsize > remaining ||
            (command.cmdsize & (sizeof(uint32_t) - 1u)) != 0) {
            return false;
        }

        if (command.cmd == LC_UUID) {
            if (found_uuid || command.cmdsize != sizeof(struct uuid_command)) {
                return false;
            }
            struct uuid_command uuidCommand;
            memcpy(&uuidCommand, cursor, sizeof(uuidCommand));
            if (memcmp(uuidCommand.uuid, rb_locked_main_image_uuid,
                       sizeof(rb_locked_main_image_uuid)) != 0) {
                return false;
            }
            found_uuid = true;
        }

        cursor += command.cmdsize;
        remaining -= command.cmdsize;
    }

    return found_uuid && remaining == 0;
}

#endif
