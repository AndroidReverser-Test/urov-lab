/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_DETECT_H
#define UROV_DETECT_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define UD_MAX_BYTES 256U
#define UD_REPEATS 3U
enum ud_verdict { UD_UNKNOWN = -1, UD_NO_MATCH = 0, UD_MATCH = 1 };
enum ud_scope { UD_SCOPE_UNKNOWN = -1, UD_SCOPE_IDLE = 0, UD_SCOPE_SELF = 1, UD_SCOPE_OTHER = 2 };

struct ud_mapping {
    uintptr_t start, end;
    uint64_t offset, inode;
    unsigned dev_major, dev_minor;
    int readable, writable, executable, shared, dontcopy, maywrite, randomread;
};
struct ud_control {
    enum ud_verdict verdict;
    int error;
    uint64_t caps;
    enum ud_scope scope;
    uint64_t generation;
    uint32_t offset, length;
};
struct ud_views {
    enum ud_verdict file_diff;
    int error_file;
    unsigned completed;
    size_t first_file_diff;
};
typedef void (*ud_bytes_reader)(uint8_t *out, const uint8_t *address, size_t size);

/* These functions preserve the caller's errno, install no signal handlers,
 * change no mapping and never register/update/deactivate a module session.
 * UD_NO_MATCH means only that this particular check found no evidence.
 *
 * Call on a worker thread. The caller MUST hold the lifetime of the sampled
 * mapping and fd (no concurrent unmap, protect, dlclose, fd close/reuse or code
 * mutation). Sample only owned immutable RX code, within one page, <=256 bytes.
 * Metadata checks cannot replace that lifetime contract. Unknown/IO errors are
 * never positive findings. No guarantee against a malicious kernel is possible.
 */
void ud_probe_control(struct ud_control *out);
int ud_mapping_at(const char *proc_file, const void *address, struct ud_mapping *out);
void ud_check_views(const void *address, size_t length, int backing_fd,
                    off_t backing_offset, struct ud_views *out);

/* Also compare a side-effect-free business reader with the independent EL0
 * reads above. The return value describes the split between those readers.
 * The file comparison is reported in out. Neither uses process_vm_readv. */
enum ud_verdict ud_check_reader_views(const uint8_t *address, size_t length, int backing_fd,
                                      off_t backing_offset, ud_bytes_reader reader,
                                      struct ud_views *out);
#endif
