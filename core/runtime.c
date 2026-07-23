#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define ENCORE_ADDRESS_SANITIZER 1
#endif
#endif
#ifdef __APPLE__
#include <crt_externs.h>
#include <mach-o/dyld.h>
#endif
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <direct.h>
#include <io.h>
#include <process.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <dlfcn.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

void *__ehir_pcast(size_t value) {
    return (void *)(uintptr_t)value;
}

#if defined(ENCORE_ADDRESS_SANITIZER)
void *__ehir_hrealloc(void *ptr, size_t bytes) { return realloc(ptr, bytes); }

void __ehir_hfree(void *ptr) { free(ptr); }
void encore_heap_retain(void *ptr) { (void)ptr; }
bool encore_heap_release(void *ptr) { (void)ptr; return true; }
#else
typedef union encore_heap_block encore_heap_block;
union encore_heap_block {
    struct {
        size_t capacity;
        size_t refs;
    } meta;
    max_align_t alignment;
};

void __ehir_hfree(void *ptr);

static void *encore_heap_alloc(size_t bytes) {
    if (bytes == 0) bytes = 1;
    encore_heap_block *block = malloc(sizeof(encore_heap_block) + bytes);
    if (block == NULL) return NULL;
    block->meta.capacity = bytes;
    block->meta.refs = 1;
    return block + 1;
}

void *__ehir_hrealloc(void *ptr, size_t bytes) {
    if (ptr == NULL) return encore_heap_alloc(bytes);
    if (bytes == 0) bytes = 1;
    encore_heap_block *block = ((encore_heap_block *)ptr) - 1;
    if (bytes <= block->meta.capacity) return ptr;
    if (block->meta.refs == 1) {
        encore_heap_block *resized = realloc(block, sizeof(encore_heap_block) + bytes);
        if (resized == NULL) return NULL;
        resized->meta.capacity = bytes;
        return resized + 1;
    }
    void *next = encore_heap_alloc(bytes);
    if (next == NULL) return NULL;
    memcpy(next, ptr, block->meta.capacity);
    block->meta.refs -= 1;
    return next;
}

void __ehir_hfree(void *ptr) {
    if (ptr == NULL) return;
    encore_heap_block *block = ((encore_heap_block *)ptr) - 1;
    if (block->meta.refs > 1) {
        block->meta.refs -= 1;
        return;
    }
    free(block);
}

void encore_heap_retain(void *ptr) {
    if (ptr == NULL) return;
    encore_heap_block *block = ((encore_heap_block *)ptr) - 1;
    block->meta.refs += 1;
}

bool encore_heap_release(void *ptr) {
    if (ptr == NULL) return false;
    encore_heap_block *block = ((encore_heap_block *)ptr) - 1;
    if (block->meta.refs > 1) {
        block->meta.refs -= 1;
        return false;
    }
    return true;
}
#endif

typedef union {
    struct {
        size_t refs;
    } meta;
    max_align_t alignment;
} encore_box_header;

void *encore_box_alloc(size_t bytes) {
    encore_box_header *header = malloc(sizeof(encore_box_header) + bytes);
    if (header == NULL) return NULL;
    header->meta.refs = 1;
    return (void *)(header + 1);
}

void encore_box_retain(void *payload) {
    if (payload == NULL) return;
    encore_box_header *header = ((encore_box_header *)payload) - 1;
    header->meta.refs += 1;
}

void encore_box_drop(void *payload) {
    if (payload == NULL) return;
    encore_box_header *header = ((encore_box_header *)payload) - 1;
    if (header->meta.refs > 1) { header->meta.refs -= 1; return; }
    free(header);
}

typedef struct {
    size_t ref_count;
    size_t len;
    char data[];
} encore_str_object;

typedef struct {
    encore_str_object *object;
} encore_str;

static encore_str encore_empty_str(void);
static encore_str encore_from_owned_buffer(char *buffer, size_t len);

static struct {
    size_t ref_count;
    size_t len;
    char data[1];
} g_empty_str_object = {.ref_count = 0, .len = 0, .data = {0}};

static char *encore_str_data(encore_str value) {
    if (value.object == NULL) {
        return g_empty_str_object.data;
    }
    return value.object->data;
}

static size_t encore_str_size(encore_str value) {
    if (value.object == NULL) {
        return 0;
    }
    return value.object->len;
}

typedef struct {
    uint64_t hash;
    size_t len;
    char *data;
} encore_strset_entry;

typedef struct {
    size_t len;
    size_t cap;
    encore_strset_entry *entries;
} encore_strset;

static uint64_t encore_strset_hash(const char *data, size_t len) {
    uint64_t hash = UINT64_C(1469598103934665603);
    for (size_t index = 0; index < len; ++index) {
        hash ^= (unsigned char)data[index];
        hash *= UINT64_C(1099511628211);
    }
    return hash == 0 ? 1 : hash;
}

static bool encore_strset_rehash(encore_strset *set, size_t next_cap) {
    encore_strset_entry *next = calloc(next_cap, sizeof(encore_strset_entry));
    if (next == NULL) return false;
    for (size_t index = 0; index < set->cap; ++index) {
        encore_strset_entry entry = set->entries[index];
        if (entry.data == NULL) continue;
        size_t slot = (size_t)(entry.hash % next_cap);
        while (next[slot].data != NULL) slot = (slot + 1) % next_cap;
        next[slot] = entry;
    }
    free(set->entries);
    set->entries = next;
    set->cap = next_cap;
    return true;
}

void *encore_strset_new(void) {
    encore_strset *set = calloc(1, sizeof(encore_strset));
    if (set == NULL) return NULL;
    if (!encore_strset_rehash(set, 64)) {
        free(set);
        return NULL;
    }
    return set;
}

bool encore_strset_insert(void *raw_set, encore_str value) {
    encore_strset *set = raw_set;
    if (set == NULL) return true;
    if ((set->len + 1) * 10 >= set->cap * 7) {
        if (!encore_strset_rehash(set, set->cap * 2)) return true;
    }
    const char *data = encore_str_data(value);
    size_t len = encore_str_size(value);
    uint64_t hash = encore_strset_hash(data, len);
    size_t slot = (size_t)(hash % set->cap);
    while (set->entries[slot].data != NULL) {
        encore_strset_entry *entry = &set->entries[slot];
        if (entry->hash == hash && entry->len == len && memcmp(entry->data, data, len) == 0) {
            return false;
        }
        slot = (slot + 1) % set->cap;
    }
    char *copy = malloc(len + 1);
    if (copy == NULL) return true;
    if (len > 0) memcpy(copy, data, len);
    copy[len] = '\0';
    set->entries[slot] = (encore_strset_entry){.hash = hash, .len = len, .data = copy};
    set->len += 1;
    return true;
}

void encore_strset_free(void *raw_set) {
    encore_strset *set = raw_set;
    if (set == NULL) return;
    for (size_t index = 0; index < set->cap; ++index) free(set->entries[index].data);
    free(set->entries);
    free(set);
}

typedef struct {
    size_t len;
    size_t cap;
    char *data;
} encore_text_builder;

static bool encore_text_builder_reserve(encore_text_builder *builder, size_t additional) {
    if (builder == NULL || additional > SIZE_MAX - builder->len) return false;
    size_t required = builder->len + additional;
    if (required <= builder->cap) return true;
    size_t next_cap = builder->cap == 0 ? 256 : builder->cap;
    while (next_cap < required) {
        if (next_cap > SIZE_MAX / 2) {
            next_cap = required;
            break;
        }
        next_cap *= 2;
    }
    char *next = realloc(builder->data, next_cap);
    if (next == NULL) return false;
    builder->data = next;
    builder->cap = next_cap;
    return true;
}

void *encore_text_builder_new(void) {
    return calloc(1, sizeof(encore_text_builder));
}

void encore_text_builder_append(void *raw_builder, encore_str value) {
    encore_text_builder *builder = raw_builder;
    size_t len = encore_str_size(value);
    if (!encore_text_builder_reserve(builder, len)) return;
    if (len > 0) memcpy(builder->data + builder->len, encore_str_data(value), len);
    builder->len += len;
}

void encore_text_builder_append_builder(void *raw_builder, void *raw_other) {
    encore_text_builder *builder = raw_builder;
    encore_text_builder *other = raw_other;
    if (builder == NULL || other == NULL || builder == other) return;
    if (encore_text_builder_reserve(builder, other->len)) {
        if (other->len > 0) memcpy(builder->data + builder->len, other->data, other->len);
        builder->len += other->len;
    }
    free(other->data);
    free(other);
}

encore_str encore_text_builder_finish(void *raw_builder) {
    encore_text_builder *builder = raw_builder;
    if (builder == NULL) return encore_empty_str();
    char *data = builder->data;
    size_t len = builder->len;
    free(builder);
    if (data == NULL) return encore_empty_str();
    return encore_from_owned_buffer(data, len);
}

static encore_str encore_empty_str(void) {
    return (encore_str){.object = (encore_str_object *)&g_empty_str_object};
}

static char *encore_to_cstr(encore_str value) {
    size_t len = encore_str_size(value);
    char *buffer = malloc(len + 1);
    if (buffer == NULL) {
        return NULL;
    }

    char *data = encore_str_data(value);
    if (len > 0 && data != NULL) {
        memcpy(buffer, data, len);
    }
    buffer[len] = '\0';
    return buffer;
}

static encore_str encore_from_owned_buffer(char *buffer, size_t len) {
    if (buffer == NULL) {
        return encore_empty_str();
    }
    /* Strings have their own precise refcount, so they do not need the
     * alias-tolerant aggregate arena. Releasing them eagerly is essential for
     * compiler workloads that create millions of temporary IR fragments. */
    encore_str_object *object = malloc(sizeof(encore_str_object) + len + 1);
    if (object == NULL) {
        free(buffer);
        return encore_empty_str();
    }
    object->ref_count = 1;
    object->len = len;
    if (len > 0) {
        memcpy(object->data, buffer, len);
    }
    object->data[len] = '\0';
    free(buffer);
    return (encore_str){.object = object};
}

static int encore_hex_digit(unsigned char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static size_t encore_utf8_encode(uint32_t value, char *out) {
    if (value <= 0x7f) { out[0] = (char)value; return 1; }
    if (value <= 0x7ff) {
        out[0] = (char)(0xc0 | (value >> 6));
        out[1] = (char)(0x80 | (value & 0x3f));
        return 2;
    }
    if (value >= 0xd800 && value <= 0xdfff) return 0;
    if (value <= 0xffff) {
        out[0] = (char)(0xe0 | (value >> 12));
        out[1] = (char)(0x80 | ((value >> 6) & 0x3f));
        out[2] = (char)(0x80 | (value & 0x3f));
        return 3;
    }
    if (value <= 0x10ffff) {
        out[0] = (char)(0xf0 | (value >> 18));
        out[1] = (char)(0x80 | ((value >> 12) & 0x3f));
        out[2] = (char)(0x80 | ((value >> 6) & 0x3f));
        out[3] = (char)(0x80 | (value & 0x3f));
        return 4;
    }
    return 0;
}

encore_str encore_str_from_codepoint(size_t value) {
    char *buffer = malloc(5);
    if (buffer == NULL) return encore_empty_str();
    size_t encoded = encore_utf8_encode((uint32_t)value, buffer);
    if (encoded == 0) {
        free(buffer);
        return encore_empty_str();
    }
    buffer[encoded] = '\0';
    return encore_from_owned_buffer(buffer, encoded);
}

encore_str encore_llvm_float_literal(encore_str value, size_t is_f32) {
    size_t len = encore_str_size(value);
    char *input = malloc(len + 1);
    if (input == NULL) return encore_empty_str();
    memcpy(input, encore_str_data(value), len);
    input[len] = '\0';
    double parsed = strtod(input, NULL);
    free(input);
    char *buffer = malloc(32);
    if (buffer == NULL) return encore_empty_str();
    union { double number; uint64_t bits; } encoded;
    encoded.number = is_f32 ? (double)(float)parsed : parsed;
    int written = snprintf(buffer, 32, "0x%016" PRIX64, encoded.bits);
    if (written <= 0) {
        free(buffer);
        return encore_empty_str();
    }
    return encore_from_owned_buffer(buffer, (size_t)written);
}

encore_str encore_unescape_string_literal(encore_str value) {
    const unsigned char *input = (const unsigned char *)encore_str_data(value);
    size_t len = encore_str_size(value);
    char *output = malloc(len + 1);
    if (output == NULL) return encore_empty_str();
    size_t read = 0, written = 0;
    while (read < len) {
        if (input[read] != '\\' || read + 1 >= len) {
            output[written++] = (char)input[read++];
            continue;
        }
        unsigned char escape = input[read + 1];
        if (escape == 'n' || escape == 't' || escape == 'r' || escape == '\\' || escape == '"') {
            output[written++] = escape == 'n' ? '\n' : escape == 't' ? '\t' : escape == 'r' ? '\r' : (char)escape;
            read += 2;
            continue;
        }
        if (escape == 'x' && read + 3 < len) {
            int high = encore_hex_digit(input[read + 2]);
            int low = encore_hex_digit(input[read + 3]);
            if (high >= 0 && low >= 0) {
                output[written++] = (char)((high << 4) | low);
                read += 4;
                continue;
            }
        }
        if (escape == 'u' && read + 3 < len && input[read + 2] == '{') {
            size_t end = read + 3;
            uint32_t codepoint = 0;
            size_t digits = 0;
            while (end < len && input[end] != '}') {
                int digit = encore_hex_digit(input[end]);
                if (digit < 0 || codepoint > 0x10ffffu / 16u) break;
                codepoint = codepoint * 16u + (uint32_t)digit;
                digits += 1;
                end += 1;
            }
            if (digits > 0 && end < len && input[end] == '}') {
                size_t encoded = encore_utf8_encode(codepoint, output + written);
                if (encoded > 0) {
                    written += encoded;
                    read = end + 1;
                    continue;
                }
            }
        }
        output[written++] = '\\';
        output[written++] = (char)escape;
        read += 2;
    }
    output[written] = '\0';
    return encore_from_owned_buffer(output, written);
}

static encore_str encore_from_cstr_copy(const char *value) {
    if (value == NULL) {
        return encore_empty_str();
    }

    size_t len = strlen(value);
    char *buffer = malloc(len + 1);
    if (buffer == NULL) {
        return encore_empty_str();
    }
    memcpy(buffer, value, len + 1);
    return encore_from_owned_buffer(buffer, len);
}

void *encore_str_from_cstr(const char *value) {
    encore_str result = encore_from_cstr_copy(value);
    return result.object;
}

encore_str encore_os_core_dir(void) {
    const char *configured = getenv("ENCORE_CORE_DIR");
    if (configured != NULL && configured[0] != '\0') {
        return encore_from_cstr_copy(configured);
    }

    const char *home = getenv("ENCORE_HOME");
    if (home != NULL && home[0] != '\0') {
        size_t len = strlen(home);
        const char *suffix = "/lib/encore/core";
        char *path = malloc(len + strlen(suffix) + 1);
        if (path != NULL) {
            memcpy(path, home, len);
            memcpy(path + len, suffix, strlen(suffix) + 1);
            return encore_from_owned_buffer(path, len + strlen(suffix));
        }
    }

    char executable[PATH_MAX];
    size_t executable_len = 0;
#ifdef _WIN32
    DWORD written = GetModuleFileNameA(NULL, executable, (DWORD)sizeof(executable));
    if (written > 0 && written < sizeof(executable)) executable_len = (size_t)written;
#elif defined(__APPLE__)
    uint32_t capacity = (uint32_t)sizeof(executable);
    if (_NSGetExecutablePath(executable, &capacity) == 0) executable_len = strlen(executable);
#else
    ssize_t written = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    if (written > 0) { executable[written] = '\0'; executable_len = (size_t)written; }
#endif
    if (executable_len > 0) {
        char *separator = strrchr(executable, '/');
#ifdef _WIN32
        char *backslash = strrchr(executable, '\\');
        if (backslash != NULL && (separator == NULL || backslash > separator)) separator = backslash;
#endif
        if (separator != NULL) {
            size_t bin_dir_len = (size_t)(separator - executable);
            const char *suffix = "/../lib/encore/core";
            char *candidate = malloc(bin_dir_len + strlen(suffix) + 1);
            if (candidate != NULL) {
                memcpy(candidate, executable, bin_dir_len);
                memcpy(candidate + bin_dir_len, suffix, strlen(suffix) + 1);
                char manifest[PATH_MAX];
                int length = snprintf(manifest, sizeof(manifest), "%s/encore.toml", candidate);
                struct stat info;
                if (length > 0 && (size_t)length < sizeof(manifest) && stat(manifest, &info) == 0) {
                    return encore_from_owned_buffer(candidate, bin_dir_len + strlen(suffix));
                }
                free(candidate);
            }
        }
    }

    const char *source = __FILE__;
    const char *separator = strrchr(source, '/');
#ifdef _WIN32
    const char *backslash = strrchr(source, '\\');
    if (backslash != NULL && (separator == NULL || backslash > separator)) separator = backslash;
#endif
    if (separator == NULL) return encore_from_cstr_copy(".");
    size_t len = (size_t)(separator - source);
    char *buffer = malloc(len + 1);
    if (buffer == NULL) return encore_empty_str();
    memcpy(buffer, source, len);
    buffer[len] = '\0';
    return encore_from_owned_buffer(buffer, len);
}

typedef struct {
    encore_str *ptr;
    size_t len;
    size_t cap;
} encore_str_vec;

encore_str encore_str_join_lines(encore_str_vec lines) {
    size_t total = lines.len > 0 ? lines.len - 1 : 0;
    for (size_t index = 0; index < lines.len; index += 1) {
        total += encore_str_size(lines.ptr[index]);
    }
    char *buffer = malloc(total + 1);
    if (buffer == NULL) {
        return encore_empty_str();
    }
    size_t offset = 0;
    for (size_t index = 0; index < lines.len; index += 1) {
        if (index > 0) {
            buffer[offset] = '\n';
            offset += 1;
        }
        size_t len = encore_str_size(lines.ptr[index]);
        if (len > 0) {
            memcpy(buffer + offset, encore_str_data(lines.ptr[index]), len);
            offset += len;
        }
    }
    buffer[offset] = '\0';
    return encore_from_owned_buffer(buffer, offset);
}

encore_str encore_str_join_lines_parts(size_t raw_ptr, size_t len) {
    encore_str_vec lines = {
        .ptr = (encore_str *)(uintptr_t)raw_ptr,
        .len = len,
        .cap = len,
    };
    return encore_str_join_lines(lines);
}

void encore_str_retain(encore_str value) {
    if (value.object == NULL || value.object->ref_count == 0) {
        return;
    }
    value.object->ref_count += 1;
}

void encore_str_drop(encore_str value) {
    if (value.object == NULL || value.object->ref_count == 0) {
        return;
    }
    if (value.object->ref_count == 0) {
        return;
    }
    value.object->ref_count -= 1;
    if (value.object->ref_count != 0) {
        return;
    }
    free(value.object);
}

static encore_str encore_format(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int needed = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (needed < 0) {
        return encore_empty_str();
    }

    char *buffer = malloc((size_t)needed + 1);
    if (buffer == NULL) {
        return encore_empty_str();
    }

    va_start(args, fmt);
    int written = vsnprintf(buffer, (size_t)needed + 1, fmt, args);
    va_end(args);
    if (written < 0) {
        free(buffer);
        return encore_empty_str();
    }

    return encore_from_owned_buffer(buffer, (size_t)written);
}

uint64_t encore_clock_ms(uint8_t kind) {
#ifdef _WIN32
    if (kind == 0) {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER value;
        value.LowPart = ft.dwLowDateTime;
        value.HighPart = ft.dwHighDateTime;
        return (uint64_t)(value.QuadPart / 10000ULL);
    }

    LARGE_INTEGER frequency;
    LARGE_INTEGER counter;
    if (QueryPerformanceFrequency(&frequency) && QueryPerformanceCounter(&counter) && frequency.QuadPart > 0) {
        return (uint64_t)((counter.QuadPart * 1000ULL) / frequency.QuadPart);
    }
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clockid_t clock_kind = kind == 0 ? CLOCK_REALTIME : CLOCK_MONOTONIC;
    if (clock_gettime(clock_kind, &ts) == 0) {
        return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
    }

    struct timeval tv;
    if (gettimeofday(&tv, NULL) == 0) {
        return ((uint64_t)tv.tv_sec * 1000ULL) + ((uint64_t)tv.tv_usec / 1000ULL);
    }
    return 0ULL;
#endif
}

bool encore_sleep_ms(uint64_t ms) {
#ifdef _WIN32
    Sleep((DWORD)ms);
    return true;
#else
    struct timespec req;
    req.tv_sec = (time_t)(ms / 1000ULL);
    req.tv_nsec = (long)((ms % 1000ULL) * 1000000ULL);

    while (nanosleep(&req, &req) != 0) {
        if (errno != EINTR) {
            return false;
        }
    }
    return true;
#endif
}

bool encore_str_eq(encore_str lhs, encore_str rhs) {
    size_t lhs_len = encore_str_size(lhs);
    size_t rhs_len = encore_str_size(rhs);
    if (lhs_len != rhs_len) {
        return false;
    }
    if (lhs_len == 0) {
        return true;
    }
    char *lhs_data = encore_str_data(lhs);
    char *rhs_data = encore_str_data(rhs);
    if (lhs_data == NULL || rhs_data == NULL) {
        return false;
    }
    return memcmp(lhs_data, rhs_data, lhs_len) == 0;
}

size_t encore_str_len(encore_str value) {
    return encore_str_size(value);
}

uint8_t encore_str_byte_at(encore_str value, size_t index) {
    size_t len = encore_str_size(value);
    char *data = encore_str_data(value);
    if (data == NULL || index >= len) {
        return 0;
    }
    return (uint8_t)data[index];
}

static size_t encore_utf8_char_width(uint8_t lead) {
    if ((lead & 0x80u) == 0u) {
        return 1;
    }
    if ((lead & 0xE0u) == 0xC0u) {
        return 2;
    }
    if ((lead & 0xF0u) == 0xE0u) {
        return 3;
    }
    if ((lead & 0xF8u) == 0xF0u) {
        return 4;
    }
    return 1;
}

static encore_str encore_str_copy_range(encore_str value, size_t start, size_t slice_len) {
    size_t len = encore_str_size(value);
    char *data = encore_str_data(value);
    if (data == NULL || start >= len) {
        return encore_empty_str();
    }

    size_t remaining = len - start;
    size_t actual_len = slice_len < remaining ? slice_len : remaining;
    char *buffer = malloc(actual_len + 1);
    if (buffer == NULL) {
        return encore_empty_str();
    }

    memcpy(buffer, data + start, actual_len);
    return encore_from_owned_buffer(buffer, actual_len);
}

size_t encore_str_char_width_at_byte(encore_str value, size_t byte_index) {
    size_t len = encore_str_size(value);
    char *data = encore_str_data(value);
    if (data == NULL || byte_index >= len) return 0;
    size_t width = encore_utf8_char_width((uint8_t)data[byte_index]);
    return byte_index + width <= len ? width : 1;
}

encore_str encore_str_char_at_byte(encore_str value, size_t byte_index) {
    size_t width = encore_str_char_width_at_byte(value, byte_index);
    if (width == 0) return encore_empty_str();
    return encore_str_copy_range(value, byte_index, width);
}

encore_str encore_str_slice_bytes(encore_str value, size_t start, size_t byte_len) {
    return encore_str_copy_range(value, start, byte_len);
}

size_t encore_str_char_len(encore_str value) {
    size_t len = encore_str_size(value);
    char *data = encore_str_data(value);
    if (data == NULL || len == 0) {
        return 0;
    }

    size_t chars = 0;
    size_t i = 0;
    while (i < len) {
        size_t width = encore_utf8_char_width((uint8_t)data[i]);
        if (i + width > len) {
            width = 1;
        }
        i += width;
        chars += 1;
    }
    return chars;
}

encore_str encore_str_char_at(encore_str value, size_t index) {
    size_t len = encore_str_size(value);
    char *data = encore_str_data(value);
    if (data == NULL || len == 0) {
        return encore_empty_str();
    }

    size_t i = 0;
    size_t char_index = 0;
    while (i < len) {
        size_t width = encore_utf8_char_width((uint8_t)data[i]);
        if (i + width > len) {
            width = 1;
        }
        if (char_index == index) {
            return encore_str_copy_range(value, i, width);
        }
        i += width;
        char_index += 1;
    }
    return encore_empty_str();
}

encore_str encore_str_slice_chars(encore_str value, size_t start, size_t char_len) {
    size_t len = encore_str_size(value);
    char *data = encore_str_data(value);
    if (data == NULL || len == 0 || char_len == 0) {
        return encore_empty_str();
    }

    size_t i = 0;
    size_t char_index = 0;
    size_t start_byte = len;
    size_t end_byte = len;

    while (i < len) {
        if (char_index == start) {
            start_byte = i;
            break;
        }
        size_t width = encore_utf8_char_width((uint8_t)data[i]);
        if (i + width > len) {
            width = 1;
        }
        i += width;
        char_index += 1;
    }

    if (start_byte == len) {
        return encore_empty_str();
    }

    i = start_byte;
    size_t taken = 0;
    while (i < len && taken < char_len) {
        size_t width = encore_utf8_char_width((uint8_t)data[i]);
        if (i + width > len) {
            width = 1;
        }
        i += width;
        taken += 1;
    }
    end_byte = i;
    return encore_str_copy_range(value, start_byte, end_byte - start_byte);
}

encore_str encore_str_slice(encore_str value, size_t start, size_t slice_len) {
    return encore_str_copy_range(value, start, slice_len);
}

encore_str encore_str_concat(encore_str lhs, encore_str rhs) {
    size_t lhs_len = encore_str_size(lhs);
    size_t rhs_len = encore_str_size(rhs);
    char *lhs_data = encore_str_data(lhs);
    char *rhs_data = encore_str_data(rhs);
    size_t total_len = lhs_len + rhs_len;
    char *buffer = malloc(total_len + 1);
    if (buffer == NULL) {
        return encore_empty_str();
    }

    if (lhs_data != NULL && lhs_len > 0) {
        memcpy(buffer, lhs_data, lhs_len);
    }
    if (rhs_data != NULL && rhs_len > 0) {
        memcpy(buffer + lhs_len, rhs_data, rhs_len);
    }

    return encore_from_owned_buffer(buffer, total_len);
}

encore_str encore_symbol_sanitize(encore_str value) {
    size_t len = encore_str_size(value);
    if (len == 0) return encore_from_cstr_copy("_");
    const unsigned char *data = (const unsigned char *)encore_str_data(value);
    char *buffer = malloc(len + 1);
    if (buffer == NULL) return encore_empty_str();
    for (size_t index = 0; index < len; ++index) {
        unsigned char ch = data[index];
        bool valid = ch == '_' || (ch >= '0' && ch <= '9') ||
                     (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
        buffer[index] = valid ? (char)ch : '_';
    }
    buffer[len] = '\0';
    return encore_from_owned_buffer(buffer, len);
}

encore_str encore_fmt_u64(uint64_t value) {
    return encore_format("%" PRIu64, value);
}

encore_str encore_fmt_i64(int64_t value) {
    return encore_format("%" PRId64, value);
}

encore_str encore_fmt_f64(double value) {
    return encore_format("%.17g", value);
}

encore_str encore_io_read(int32_t fd, size_t max_bytes) {
    if (fd < 0 || max_bytes == 0 || max_bytes > SIZE_MAX - 1) {
        return encore_empty_str();
    }

    char *buffer = malloc(max_bytes + 1);
    if (buffer == NULL) {
        return encore_empty_str();
    }

#ifdef _WIN32
    size_t request = max_bytes > UINT_MAX ? UINT_MAX : max_bytes;
    int bytes_read = _read(fd, buffer, (unsigned int)request);
    if (bytes_read <= 0) {
        free(buffer);
        return encore_empty_str();
    }
    return encore_from_owned_buffer(buffer, (size_t)bytes_read);
#else
    ssize_t bytes_read = read(fd, buffer, max_bytes);
    if (bytes_read <= 0) {
        free(buffer);
        return encore_empty_str();
    }
    return encore_from_owned_buffer(buffer, (size_t)bytes_read);
#endif
}

int32_t encore_io_write(int32_t fd, encore_str value) {
    if (fd < 0) {
        return -1;
    }
    size_t len = encore_str_size(value);
    char *data = encore_str_data(value);
    if (len == 0) {
        return 0;
    }
    if (data == NULL) {
        return -1;
    }

    size_t offset = 0;
    while (offset < len) {
#ifdef _WIN32
        size_t remaining = len - offset;
        size_t request = remaining > UINT_MAX ? UINT_MAX : remaining;
        int written = _write(fd, data + offset, (unsigned int)request);
        if (written <= 0) {
            return -1;
        }
        offset += (size_t)written;
#else
        ssize_t written = write(fd, data + offset, len - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (written == 0) {
            return -1;
        }
        offset += (size_t)written;
#endif
    }

    if (fd == 1) {
        fflush(stdout);
    } else if (fd == 2) {
        fflush(stderr);
    }
    return 0;
}

static char g_net_last_error[256] = {0};

static void encore_set_net_error_cstr(const char *msg) {
    if (msg == NULL) {
        g_net_last_error[0] = '\0';
        return;
    }
    snprintf(g_net_last_error, sizeof(g_net_last_error), "%s", msg);
}

static void encore_set_net_error_code(const char *prefix, int code) {
    if (prefix == NULL) {
        prefix = "net";
    }
#ifdef _WIN32
    snprintf(g_net_last_error, sizeof(g_net_last_error), "%s: %d", prefix, code);
#else
    snprintf(g_net_last_error, sizeof(g_net_last_error), "%s: %s", prefix, strerror(code));
#endif
}

encore_str encore_net_last_error(void) {
    if (g_net_last_error[0] == '\0') {
        return encore_empty_str();
    }
    return encore_from_cstr_copy(g_net_last_error);
}

#ifdef _WIN32
static bool g_winsock_initialized = false;

static bool encore_net_init(void) {
    if (g_winsock_initialized) {
        return true;
    }
    WSADATA wsa_data;
    int rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (rc != 0) {
        encore_set_net_error_code("WSAStartup failed", rc);
        return false;
    }
    g_winsock_initialized = true;
    return true;
}

static int encore_last_socket_error(void) {
    return WSAGetLastError();
}

static int encore_close_socket(SOCKET fd) {
    return closesocket(fd);
}
#else
static bool encore_net_init(void) {
    return true;
}

static int encore_last_socket_error(void) {
    return errno;
}

static int encore_close_socket(int fd) {
    return close(fd);
}
#endif

static int32_t encore_parse_port(const char *port_c) {
    if (port_c == NULL) {
        return -1;
    }
    char *end = NULL;
    long parsed = strtol(port_c, &end, 10);
    bool ok = end != NULL && *end == '\0' && parsed >= 0 && parsed <= 65535;
    if (!ok) {
        return -1;
    }
    return (int32_t)parsed;
}

int32_t encore_net_tcp_connect(encore_str addr) {
    if (!encore_net_init()) {
        return -1;
    }

    char *addr_c = encore_to_cstr(addr);
    if (addr_c == NULL) {
        encore_set_net_error_cstr("alloc failed");
        return -1;
    }

    char *colon = strrchr(addr_c, ':');
    if (colon == NULL) {
        free(addr_c);
        encore_set_net_error_cstr("invalid addr, expected host:port");
        return -1;
    }
    *colon = '\0';
    const char *host = addr_c;
    int32_t port = encore_parse_port(colon + 1);
    if (port < 0) {
        free(addr_c);
        encore_set_net_error_cstr("invalid port");
        return -1;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_buf[16];
    snprintf(port_buf, sizeof(port_buf), "%d", (int)port);
    struct addrinfo *results = NULL;
    int gai_rc = getaddrinfo(host, port_buf, &hints, &results);
    if (gai_rc != 0 || results == NULL) {
        free(addr_c);
        encore_set_net_error_cstr("getaddrinfo failed");
        return -1;
    }

    int32_t out_fd = -1;
    for (struct addrinfo *it = results; it != NULL; it = it->ai_next) {
#ifdef _WIN32
        SOCKET fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd == INVALID_SOCKET) {
            continue;
        }
        if (connect(fd, it->ai_addr, (int)it->ai_addrlen) == 0) {
            out_fd = (int32_t)fd;
            break;
        }
        encore_close_socket(fd);
#else
        int fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) {
            out_fd = (int32_t)fd;
            break;
        }
        encore_close_socket(fd);
#endif
    }
    if (out_fd < 0) {
        encore_set_net_error_code("connect failed", encore_last_socket_error());
    }

    freeaddrinfo(results);
    free(addr_c);
    return out_fd;
}

int32_t encore_net_tcp_bind(encore_str addr) {
    if (!encore_net_init()) {
        return -1;
    }

    char *addr_c = encore_to_cstr(addr);
    if (addr_c == NULL) {
        encore_set_net_error_cstr("alloc failed");
        return -1;
    }
    char *colon = strrchr(addr_c, ':');
    if (colon == NULL) {
        free(addr_c);
        encore_set_net_error_cstr("invalid addr, expected host:port");
        return -1;
    }
    *colon = '\0';
    const char *host = addr_c;
    int32_t port = encore_parse_port(colon + 1);
    if (port < 0) {
        free(addr_c);
        encore_set_net_error_cstr("invalid port");
        return -1;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char port_buf[16];
    snprintf(port_buf, sizeof(port_buf), "%d", (int)port);
    struct addrinfo *results = NULL;
    int gai_rc = getaddrinfo(host, port_buf, &hints, &results);
    if (gai_rc != 0 || results == NULL) {
        free(addr_c);
        encore_set_net_error_cstr("getaddrinfo failed");
        return -1;
    }

    int32_t out_fd = -1;
    for (struct addrinfo *it = results; it != NULL; it = it->ai_next) {
#ifdef _WIN32
        SOCKET fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd == INVALID_SOCKET) {
            continue;
        }
        BOOL reuse = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));
        if (bind(fd, it->ai_addr, (int)it->ai_addrlen) == 0 && listen(fd, 64) == 0) {
            out_fd = (int32_t)fd;
            break;
        }
        encore_close_socket(fd);
#else
        int fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            continue;
        }
        int reuse = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        if (bind(fd, it->ai_addr, it->ai_addrlen) == 0 && listen(fd, 64) == 0) {
            out_fd = (int32_t)fd;
            break;
        }
        encore_close_socket(fd);
#endif
    }
    if (out_fd < 0) {
        encore_set_net_error_code("bind/listen failed", encore_last_socket_error());
    }

    freeaddrinfo(results);
    free(addr_c);
    return out_fd;
}

int32_t encore_net_tcp_accept(int32_t listener_fd) {
    if (!encore_net_init()) {
        return -1;
    }
#ifdef _WIN32
    SOCKET fd = accept((SOCKET)listener_fd, NULL, NULL);
    if (fd == INVALID_SOCKET) {
        encore_set_net_error_code("accept failed", encore_last_socket_error());
        return -1;
    }
    return (int32_t)fd;
#else
    int fd = accept(listener_fd, NULL, NULL);
    if (fd < 0) {
        encore_set_net_error_code("accept failed", errno);
        return -1;
    }
    return fd;
#endif
}

encore_str encore_net_tcp_read(int32_t fd, size_t max) {
    if (max == 0) {
        return encore_empty_str();
    }
    char *buffer = malloc(max + 1);
    if (buffer == NULL) {
        encore_set_net_error_cstr("alloc failed");
        return encore_empty_str();
    }
#ifdef _WIN32
    int n = recv((SOCKET)fd, buffer, (int)max, 0);
    if (n < 0) {
        free(buffer);
        encore_set_net_error_code("recv failed", encore_last_socket_error());
        return encore_empty_str();
    }
    return encore_from_owned_buffer(buffer, (size_t)n);
#else
    ssize_t n = recv(fd, buffer, max, 0);
    if (n < 0) {
        free(buffer);
        encore_set_net_error_code("recv failed", errno);
        return encore_empty_str();
    }
    return encore_from_owned_buffer(buffer, (size_t)n);
#endif
}

int32_t encore_net_tcp_write(int32_t fd, encore_str data) {
    size_t len = encore_str_size(data);
    char *bytes = encore_str_data(data);
    if (bytes == NULL && len > 0) {
        encore_set_net_error_cstr("invalid data");
        return -1;
    }
#ifdef _WIN32
    int n = send((SOCKET)fd, bytes, (int)len, 0);
    if (n < 0) {
        encore_set_net_error_code("send failed", encore_last_socket_error());
        return -1;
    }
    return n;
#else
    ssize_t n = send(fd, bytes, len, 0);
    if (n < 0) {
        encore_set_net_error_code("send failed", errno);
        return -1;
    }
    return (int32_t)n;
#endif
}

int32_t encore_net_tcp_close(int32_t fd) {
    int rc = encore_close_socket(
#ifdef _WIN32
        (SOCKET)fd
#else
        fd
#endif
    );
    if (rc != 0) {
        encore_set_net_error_code("close failed", encore_last_socket_error());
        return -1;
    }
    return 0;
}

int32_t encore_proc_exit(int32_t code) {
    /* The Encore standard library also exports a function named `exit`.
       Calling libc's exit here can therefore bind back to the generated
       symbol and recurse forever. `_Exit` has no generated-name collision. */
    _Exit(code);
    return code;
}

int32_t encore_proc_run(encore_str command) {
    char *command_c = encore_to_cstr(command);
    if (command_c == NULL) {
        return -1;
    }

    int rc = system(command_c);
    free(command_c);
    if (rc == -1) {
        return -1;
    }
#ifdef _WIN32
    return rc;
#else
    if (WIFEXITED(rc)) {
        return WEXITSTATUS(rc);
    }
    if (WIFSIGNALED(rc)) {
        return 128 + WTERMSIG(rc);
    }
    return rc;
#endif
}

static int32_t encore_proc_run_args_impl(encore_str program, size_t raw_args, size_t args_len, const char *output_path) {
    encore_str *args = (encore_str *)(uintptr_t)raw_args;
    char *program_c = encore_to_cstr(program);
    if (program_c == NULL) return -1;
    char **argv = calloc(args_len + 2, sizeof(char *));
    if (argv == NULL) { free(program_c); return -1; }
    argv[0] = program_c;
    size_t converted = 0;
    for (; converted < args_len; converted += 1) {
        argv[converted + 1] = encore_to_cstr(args[converted]);
        if (argv[converted + 1] == NULL) break;
    }
    if (converted != args_len) {
        for (size_t index = 0; index <= converted; index += 1) free(argv[index]);
        free(argv);
        return -1;
    }

    int32_t result = -1;
#ifdef _WIN32
    int saved_stdout = -1;
    int saved_stderr = -1;
    int output_fd = -1;
    if (output_path != NULL) {
        output_fd = _open(output_path, _O_CREAT | _O_TRUNC | _O_WRONLY | _O_BINARY, _S_IREAD | _S_IWRITE);
        if (output_fd < 0) goto cleanup;
        saved_stdout = _dup(1);
        saved_stderr = _dup(2);
        if (saved_stdout < 0 || saved_stderr < 0 || _dup2(output_fd, 1) != 0 || _dup2(output_fd, 2) != 0) goto cleanup;
    }
    intptr_t status = _spawnvp(_P_WAIT, program_c, (const char *const *)argv);
    if (status >= 0 && status <= INT32_MAX) result = (int32_t)status;
cleanup:
    if (saved_stdout >= 0) { fflush(stdout); _dup2(saved_stdout, 1); _close(saved_stdout); }
    if (saved_stderr >= 0) { fflush(stderr); _dup2(saved_stderr, 2); _close(saved_stderr); }
    if (output_fd >= 0) _close(output_fd);
#else
    pid_t child = fork();
    if (child == 0) {
        if (output_path != NULL) {
            int output_fd = open(output_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (output_fd < 0 || dup2(output_fd, STDOUT_FILENO) < 0 || dup2(output_fd, STDERR_FILENO) < 0) _Exit(126);
            close(output_fd);
        }
        execvp(program_c, argv);
        _Exit(127);
    }
    if (child > 0) {
        int status = 0;
        if (waitpid(child, &status, 0) >= 0) {
            if (WIFEXITED(status)) result = WEXITSTATUS(status);
            else if (WIFSIGNALED(status)) result = 128 + WTERMSIG(status);
        }
    }
#endif
    for (size_t index = 0; index < args_len + 1; index += 1) free(argv[index]);
    free(argv);
    return result;
}

int32_t encore_proc_run_args_parts(encore_str program, size_t raw_args, size_t args_len) {
    return encore_proc_run_args_impl(program, raw_args, args_len, NULL);
}

int32_t encore_proc_run_args_capture_parts(encore_str program, size_t raw_args, size_t args_len, encore_str output_path) {
    char *output_c = encore_to_cstr(output_path);
    if (output_c == NULL) return -1;
    int32_t result = encore_proc_run_args_impl(program, raw_args, args_len, output_c);
    free(output_c);
    return result;
}

/* Compatibility with bootstrap objects emitted before Vec extern arguments
 * were lowered to scalar ABI parts. LLVM passes this aggregate in registers. */
int32_t encore_proc_run_args(encore_str program, encore_str *args, size_t len, size_t cap) {
    (void)cap;
    return encore_proc_run_args_parts(program, (size_t)(uintptr_t)args, len);
}

static bool g_args_initialized = false;
static size_t g_argc = 0;
static char **g_argv = NULL;

static void encore_free_args(void) {
    if (g_argv == NULL) {
        return;
    }
    for (size_t i = 0; i < g_argc; ++i) {
        free(g_argv[i]);
    }
    free(g_argv);
    g_argv = NULL;
    g_argc = 0;
}

static void encore_init_args(void) {
    if (g_args_initialized) {
        return;
    }
    g_args_initialized = true;
    atexit(encore_free_args);

#ifdef _WIN32
#ifdef __MINGW32__
    int argc = __argc;
    char **argv = __argv;
#else
    int argc = *__p___argc();
    char **argv = *__p___argv();
#endif
    if (argc <= 0 || argv == NULL) {
        return;
    }
    g_argc = (size_t)argc;
    g_argv = calloc(g_argc, sizeof(char *));
    if (g_argv == NULL) {
        g_argc = 0;
        return;
    }
    for (size_t i = 0; i < g_argc; ++i) {
        if (argv[i] != NULL) {
            size_t len = strlen(argv[i]);
            g_argv[i] = malloc(len + 1);
            if (g_argv[i] != NULL) {
                memcpy(g_argv[i], argv[i], len + 1);
            }
        }
    }
    return;
#endif

#ifdef __APPLE__
    int argc = *_NSGetArgc();
    char **argv = *_NSGetArgv();
    if (argc <= 0 || argv == NULL) {
        return;
    }
    g_argc = (size_t)argc;
    g_argv = calloc(g_argc, sizeof(char *));
    if (g_argv == NULL) {
        g_argc = 0;
        return;
    }
    for (size_t i = 0; i < g_argc; ++i) {
        if (argv[i] != NULL) {
            g_argv[i] = strdup(argv[i]);
        }
    }
    return;
#endif

    FILE *file = fopen("/proc/self/cmdline", "rb");
    if (file == NULL) {
        return;
    }
    size_t capacity = 256;
    size_t read_count = 0;
    char *buffer = malloc(capacity);
    if (buffer == NULL) {
        fclose(file);
        return;
    }

    while (true) {
        if (read_count == capacity) {
            size_t next_capacity = capacity * 2;
            char *next_buffer = realloc(buffer, next_capacity);
            if (next_buffer == NULL) {
                free(buffer);
                fclose(file);
                return;
            }
            buffer = next_buffer;
            capacity = next_capacity;
        }

        size_t chunk = fread(buffer + read_count, 1, capacity - read_count, file);
        read_count += chunk;
        if (chunk == 0) {
            break;
        }
    }
    fclose(file);
    if (read_count == 0) {
        free(buffer);
        return;
    }

    for (size_t i = 0; i < read_count; ++i) {
        if (buffer[i] == '\0') {
            g_argc += 1;
        }
    }
    if (g_argc == 0) {
        free(buffer);
        return;
    }

    g_argv = calloc(g_argc, sizeof(char *));
    if (g_argv == NULL) {
        g_argc = 0;
        free(buffer);
        return;
    }

    size_t arg_index = 0;
    size_t start = 0;
    for (size_t i = 0; i < read_count; ++i) {
        if (buffer[i] != '\0') {
            continue;
        }

        size_t len = i - start;
        char *arg = malloc(len + 1);
        if (arg == NULL) {
            start = i + 1;
            continue;
        }
        memcpy(arg, buffer + start, len);
        arg[len] = '\0';
        g_argv[arg_index++] = arg;
        start = i + 1;
    }

    free(buffer);
}

size_t encore_os_argc(void) {
    encore_init_args();
    return g_argc;
}

encore_str encore_os_argv(size_t index) {
    encore_init_args();
    if (index >= g_argc || g_argv == NULL || g_argv[index] == NULL) {
        return encore_empty_str();
    }
    return encore_from_cstr_copy(g_argv[index]);
}

encore_str encore_os_cwd(void) {
    size_t size = 256;

    for (;;) {
        char *buffer = malloc(size);
        if (buffer == NULL) {
            return encore_empty_str();
        }

        char *cwd_result =
#ifdef _WIN32
            _getcwd(buffer, (int)size);
#else
            getcwd(buffer, size);
#endif
        if (cwd_result != NULL) {
            size_t len = strlen(buffer);
            return encore_from_owned_buffer(buffer, len);
        }

        free(buffer);
        if (errno != ERANGE) {
            return encore_empty_str();
        }

        if (size > (SIZE_MAX / 2)) {
            return encore_empty_str();
        }
        size *= 2;
    }
}

encore_str encore_os_home_dir(void) {
#ifdef _WIN32
    const char *home = getenv("USERPROFILE");
    if (home == NULL || home[0] == '\0') {
        const char *drive = getenv("HOMEDRIVE");
        const char *path = getenv("HOMEPATH");
        if (drive != NULL && path != NULL) {
            size_t drive_len = strlen(drive);
            size_t path_len = strlen(path);
            char *buffer = malloc(drive_len + path_len + 1);
            if (buffer == NULL) {
                return encore_empty_str();
            }
            memcpy(buffer, drive, drive_len);
            memcpy(buffer + drive_len, path, path_len + 1);
            return encore_from_owned_buffer(buffer, drive_len + path_len);
        }
    }
#else
    const char *home = getenv("HOME");
#endif
    if (home == NULL || home[0] == '\0') {
        return encore_empty_str();
    }
    return encore_from_cstr_copy(home);
}

encore_str encore_os_arch(void) {
#ifdef _WIN32
    SYSTEM_INFO info;
    GetNativeSystemInfo(&info);
    switch (info.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: return encore_from_cstr_copy("x86_64");
        case PROCESSOR_ARCHITECTURE_ARM64: return encore_from_cstr_copy("aarch64");
        case PROCESSOR_ARCHITECTURE_INTEL: return encore_from_cstr_copy("i686");
        case PROCESSOR_ARCHITECTURE_ARM: return encore_from_cstr_copy("arm");
        default: return encore_from_cstr_copy("unknown");
    }
#else
    struct utsname info;
    if (uname(&info) != 0) return encore_from_cstr_copy("unknown");
    if (strcmp(info.machine, "amd64") == 0) return encore_from_cstr_copy("x86_64");
    if (strcmp(info.machine, "arm64") == 0) return encore_from_cstr_copy("aarch64");
    return encore_from_cstr_copy(info.machine);
#endif
}

encore_str encore_os_getenv(encore_str name) {
    char *name_c = encore_to_cstr(name);
    if (name_c == NULL) return encore_empty_str();
    const char *value = getenv(name_c);
    free(name_c);
    if (value == NULL || value[0] == '\0') return encore_empty_str();
    return encore_from_cstr_copy(value);
}

encore_str encore_fs_read_file(encore_str path) {
    char *path_c = encore_to_cstr(path);
    if (path_c == NULL) {
        return encore_empty_str();
    }

    FILE *file = fopen(path_c, "rb");
    free(path_c);
    if (file == NULL) {
        return encore_empty_str();
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return encore_empty_str();
    }
    long length = ftell(file);
    if (length < 0) {
        fclose(file);
        return encore_empty_str();
    }
    rewind(file);

    char *buffer = malloc((size_t)length + 1);
    if (buffer == NULL) {
        fclose(file);
        return encore_empty_str();
    }

    size_t read_count = fread(buffer, 1, (size_t)length, file);
    fclose(file);
    return encore_from_owned_buffer(buffer, read_count);
}

int32_t encore_fs_write_file(encore_str path, encore_str contents) {
    char *path_c = encore_to_cstr(path);
    if (path_c == NULL) {
        return -1;
    }

    FILE *file = fopen(path_c, "wb");
    free(path_c);
    if (file == NULL) {
        return -1;
    }

    size_t contents_len = encore_str_size(contents);
    char *contents_data = encore_str_data(contents);
    size_t written = fwrite(contents_data, 1, contents_len, file);
    fclose(file);
    return written == contents_len ? 0 : -1;
}

int32_t encore_fs_status(encore_str path) {
    char *path_c = encore_to_cstr(path);
    if (path_c == NULL) {
        return -1;
    }

    struct stat st;
    int32_t result = stat(path_c, &st) == 0 ? 0 : -1;
    free(path_c);
    return result;
}

int32_t encore_fs_remove_file(encore_str path) {
    char *path_c = encore_to_cstr(path);
    if (path_c == NULL) {
        return -1;
    }

    int result = remove(path_c);
    free(path_c);
    return result == 0 ? 0 : -1;
}

int32_t encore_fs_copy_file(encore_str source, encore_str destination) {
    char *source_c = encore_to_cstr(source);
    char *destination_c = encore_to_cstr(destination);
    if (source_c == NULL || destination_c == NULL) { free(source_c); free(destination_c); return -1; }
    FILE *input = fopen(source_c, "rb");
    FILE *output = input == NULL ? NULL : fopen(destination_c, "wb");
    free(source_c);
    free(destination_c);
    if (input == NULL || output == NULL) { if (input != NULL) fclose(input); if (output != NULL) fclose(output); return -1; }
    char buffer[65536];
    int32_t status = 0;
    for (;;) {
        size_t count = fread(buffer, 1, sizeof(buffer), input);
        if (count > 0 && fwrite(buffer, 1, count, output) != count) { status = -1; break; }
        if (count < sizeof(buffer)) { if (ferror(input)) status = -1; break; }
    }
    if (fclose(input) != 0 || fclose(output) != 0) status = -1;
    return status;
}

int32_t encore_fs_set_executable(encore_str path) {
#ifdef _WIN32
    (void)path;
    return 0;
#else
    char *path_c = encore_to_cstr(path);
    if (path_c == NULL) return -1;
    struct stat info;
    int32_t status = stat(path_c, &info) == 0 && chmod(path_c, info.st_mode | S_IXUSR | S_IXGRP | S_IXOTH) == 0 ? 0 : -1;
    free(path_c);
    return status;
#endif
}

int32_t encore_fs_mkdir(encore_str path) {
    char *path_c = encore_to_cstr(path);
    if (path_c == NULL) {
        return -1;
    }

    int rc =
#ifdef _WIN32
        _mkdir(path_c);
#else
        mkdirat(AT_FDCWD, path_c, 0755);
#endif
    int32_t status = (rc == 0 || errno == EEXIST) ? 0 : -1;
    free(path_c);
    return status;
}

int32_t encore_fs_mkdir_all(encore_str path) {
    char *path_c = encore_to_cstr(path);
    if (path_c == NULL || path_c[0] == '\0') { free(path_c); return -1; }
    size_t len = strlen(path_c);
    for (size_t index = 1; index <= len; index += 1) {
        bool boundary = index == len || path_c[index] == '/' || path_c[index] == '\\';
        if (!boundary) continue;
#ifdef _WIN32
        if (index == 2 && path_c[1] == ':') continue;
#endif
        char saved = path_c[index];
        path_c[index] = '\0';
        if (path_c[0] != '\0') {
            int rc =
#ifdef _WIN32
                _mkdir(path_c);
#else
                mkdirat(AT_FDCWD, path_c, 0755);
#endif
            if (rc != 0 && errno != EEXIST) { free(path_c); return -1; }
        }
        path_c[index] = saved;
    }
    free(path_c);
    return 0;
}

static bool encore_append_dir_entry(char **buffer, size_t *cap, size_t *len, const char *name) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        return true;
    }

    size_t name_len = strlen(name);
    size_t need = *len + name_len + 1;
    if (need > *cap) {
        size_t next_cap = *cap;
        while (need > next_cap) {
            if (next_cap > (SIZE_MAX / 2)) {
                return false;
            }
            next_cap *= 2;
        }
        char *next = realloc(*buffer, next_cap + 1);
        if (next == NULL) {
            return false;
        }
        *buffer = next;
        *cap = next_cap;
    }

    memcpy(*buffer + *len, name, name_len);
    *len += name_len;
    (*buffer)[(*len)++] = '\n';
    return true;
}

encore_str encore_fs_read_dir(encore_str path) {
    char *path_c = encore_to_cstr(path);
    if (path_c == NULL) {
        return encore_empty_str();
    }

#ifdef _WIN32
    size_t path_len = strlen(path_c);
    const char *suffix = (path_len > 0 && (path_c[path_len - 1] == '\\' || path_c[path_len - 1] == '/')) ? "*" : "\\*";
    char *pattern = malloc(path_len + strlen(suffix) + 1);
    if (pattern == NULL) {
        free(path_c);
        return encore_empty_str();
    }
    strcpy(pattern, path_c);
    strcat(pattern, suffix);
    free(path_c);

    WIN32_FIND_DATAA data;
    HANDLE handle = FindFirstFileA(pattern, &data);
    free(pattern);
    if (handle == INVALID_HANDLE_VALUE) {
        return encore_empty_str();
    }
#else
    DIR *dir = opendir(path_c);
    free(path_c);
    if (dir == NULL) {
        return encore_empty_str();
    }
#endif

    size_t cap = 256;
    size_t len = 0;
    char *buffer = malloc(cap + 1);
    if (buffer == NULL) {
#ifdef _WIN32
        FindClose(handle);
#else
        closedir(dir);
#endif
        return encore_empty_str();
    }

#ifdef _WIN32
    do {
        if (!encore_append_dir_entry(&buffer, &cap, &len, data.cFileName)) {
            free(buffer);
            FindClose(handle);
            return encore_empty_str();
        }
    } while (FindNextFileA(handle, &data));
    FindClose(handle);
#else
    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (!encore_append_dir_entry(&buffer, &cap, &len, entry->d_name)) {
            free(buffer);
            closedir(dir);
            return encore_empty_str();
        }
    }
    closedir(dir);
#endif

    if (len > 0 && buffer[len - 1] == '\n') {
        len -= 1;
    }
    return encore_from_owned_buffer(buffer, len);
}

#ifndef _WIN32
typedef void EncoreGuiDisplay;
typedef void *EncoreGuiGc;
typedef unsigned long EncoreGuiWindowId;
typedef unsigned long EncoreGuiAtom;

typedef struct {
    bool initialized;
    bool available;
    void *lib;

    EncoreGuiDisplay *(*XOpenDisplay)(const char *);
    int (*XDefaultScreen)(EncoreGuiDisplay *);
    EncoreGuiWindowId (*XRootWindow)(EncoreGuiDisplay *, int);
    unsigned long (*XBlackPixel)(EncoreGuiDisplay *, int);
    unsigned long (*XWhitePixel)(EncoreGuiDisplay *, int);
    EncoreGuiWindowId (*XCreateSimpleWindow)(
        EncoreGuiDisplay *,
        EncoreGuiWindowId,
        int,
        int,
        unsigned int,
        unsigned int,
        unsigned int,
        unsigned long,
        unsigned long);
    int (*XStoreName)(EncoreGuiDisplay *, EncoreGuiWindowId, const char *);
    int (*XSelectInput)(EncoreGuiDisplay *, EncoreGuiWindowId, long);
    int (*XMapWindow)(EncoreGuiDisplay *, EncoreGuiWindowId);
    EncoreGuiGc (*XCreateGC)(EncoreGuiDisplay *, EncoreGuiWindowId, unsigned long, void *);
    int (*XFreeGC)(EncoreGuiDisplay *, EncoreGuiGc);
    int (*XSetForeground)(EncoreGuiDisplay *, EncoreGuiGc, unsigned long);
    int (*XFillRectangle)(EncoreGuiDisplay *, EncoreGuiWindowId, EncoreGuiGc, int, int, unsigned int, unsigned int);
    int (*XFlush)(EncoreGuiDisplay *);
    int (*XPending)(EncoreGuiDisplay *);
    int (*XNextEvent)(EncoreGuiDisplay *, void *);
    int (*XDestroyWindow)(EncoreGuiDisplay *, EncoreGuiWindowId);
    int (*XCloseDisplay)(EncoreGuiDisplay *);
    EncoreGuiAtom (*XInternAtom)(EncoreGuiDisplay *, const char *, int);
    int (*XSetWMProtocols)(EncoreGuiDisplay *, EncoreGuiWindowId, EncoreGuiAtom *, int);
} EncoreGuiX11Api;

typedef struct {
    EncoreGuiDisplay *display;
    EncoreGuiWindowId window;
    EncoreGuiGc gc;
    EncoreGuiAtom wm_delete;
    bool open;
    uint32_t width;
    uint32_t height;
} EncoreGuiWindow;

typedef struct {
    int type;
    unsigned long serial;
    int send_event;
    EncoreGuiDisplay *display;
    EncoreGuiWindowId window;
    EncoreGuiAtom message_type;
    int format;
    union {
        char b[20];
        short s[10];
        long l[5];
    } data;
} EncoreGuiXClientMessageEvent;

static EncoreGuiX11Api g_gui_x11 = {0};

#define ENCORE_X11_LOAD(field)                                                            \
    do {                                                                                  \
        *(void **)(&g_gui_x11.field) = dlsym(g_gui_x11.lib, #field);                      \
        if (g_gui_x11.field == NULL) {                                                     \
            dlclose(g_gui_x11.lib);                                                        \
            memset(&g_gui_x11, 0, sizeof(g_gui_x11));                                      \
            g_gui_x11.initialized = true;                                                  \
            return false;                                                                  \
        }                                                                                  \
    } while (0)

static bool encore_gui_x11_load(void) {
    if (g_gui_x11.initialized) {
        return g_gui_x11.available;
    }

    g_gui_x11.initialized = true;
    g_gui_x11.lib = dlopen("libX11.so.6", RTLD_LAZY | RTLD_LOCAL);
    if (g_gui_x11.lib == NULL) {
        g_gui_x11.lib = dlopen("libX11.so", RTLD_LAZY | RTLD_LOCAL);
    }
    if (g_gui_x11.lib == NULL) {
        return false;
    }

    ENCORE_X11_LOAD(XOpenDisplay);
    ENCORE_X11_LOAD(XDefaultScreen);
    ENCORE_X11_LOAD(XRootWindow);
    ENCORE_X11_LOAD(XBlackPixel);
    ENCORE_X11_LOAD(XWhitePixel);
    ENCORE_X11_LOAD(XCreateSimpleWindow);
    ENCORE_X11_LOAD(XStoreName);
    ENCORE_X11_LOAD(XSelectInput);
    ENCORE_X11_LOAD(XMapWindow);
    ENCORE_X11_LOAD(XCreateGC);
    ENCORE_X11_LOAD(XFreeGC);
    ENCORE_X11_LOAD(XSetForeground);
    ENCORE_X11_LOAD(XFillRectangle);
    ENCORE_X11_LOAD(XFlush);
    ENCORE_X11_LOAD(XPending);
    ENCORE_X11_LOAD(XNextEvent);
    ENCORE_X11_LOAD(XDestroyWindow);
    ENCORE_X11_LOAD(XCloseDisplay);
    ENCORE_X11_LOAD(XInternAtom);
    ENCORE_X11_LOAD(XSetWMProtocols);

    g_gui_x11.available = true;
    return true;
}

#undef ENCORE_X11_LOAD

static EncoreGuiWindow *encore_gui_window_from_handle(size_t handle) {
    if (handle == 0) {
        return NULL;
    }
    return (EncoreGuiWindow *)(uintptr_t)handle;
}

size_t encore_gui_window_create(encore_str title, uint32_t width, uint32_t height) {
    if (width == 0 || height == 0 || !encore_gui_x11_load()) {
        return 0;
    }

    EncoreGuiDisplay *display = g_gui_x11.XOpenDisplay(NULL);
    if (display == NULL) {
        return 0;
    }

    EncoreGuiWindow *state = calloc(1, sizeof(EncoreGuiWindow));
    if (state == NULL) {
        g_gui_x11.XCloseDisplay(display);
        return 0;
    }

    int screen = g_gui_x11.XDefaultScreen(display);
    EncoreGuiWindowId root = g_gui_x11.XRootWindow(display, screen);
    unsigned long black = g_gui_x11.XBlackPixel(display, screen);
    unsigned long white = g_gui_x11.XWhitePixel(display, screen);

    EncoreGuiWindowId window = g_gui_x11.XCreateSimpleWindow(display, root, 0, 0, width, height, 0, black, white);
    if (window == 0) {
        free(state);
        g_gui_x11.XCloseDisplay(display);
        return 0;
    }

    EncoreGuiGc gc = g_gui_x11.XCreateGC(display, window, 0, NULL);
    if (gc == NULL) {
        g_gui_x11.XDestroyWindow(display, window);
        free(state);
        g_gui_x11.XCloseDisplay(display);
        return 0;
    }

    char *title_c = encore_to_cstr(title);
    if (title_c != NULL) {
        g_gui_x11.XStoreName(display, window, title_c);
        free(title_c);
    }

    const long event_mask = (1L << 15) | (1L << 17) | (1L << 0);
    g_gui_x11.XSelectInput(display, window, event_mask);

    EncoreGuiAtom wm_delete = g_gui_x11.XInternAtom(display, "WM_DELETE_WINDOW", 0);
    if (wm_delete != 0) {
        g_gui_x11.XSetWMProtocols(display, window, &wm_delete, 1);
    }

    g_gui_x11.XMapWindow(display, window);
    g_gui_x11.XFlush(display);

    state->display = display;
    state->window = window;
    state->gc = gc;
    state->wm_delete = wm_delete;
    state->open = true;
    state->width = width;
    state->height = height;

    return (size_t)(uintptr_t)state;
}

bool encore_gui_window_is_open(size_t handle) {
    EncoreGuiWindow *state = encore_gui_window_from_handle(handle);
    return state != NULL && state->open;
}

bool encore_gui_window_poll(size_t handle) {
    EncoreGuiWindow *state = encore_gui_window_from_handle(handle);
    if (state == NULL || !state->open) {
        return false;
    }

    while (g_gui_x11.XPending(state->display) > 0) {
        long event_storage[24];
        memset(event_storage, 0, sizeof(event_storage));
        g_gui_x11.XNextEvent(state->display, event_storage);

        int type = *((int *)event_storage);
        if (type == 17) {
            state->open = false;
        } else if (type == 33 && state->wm_delete != 0) {
            EncoreGuiXClientMessageEvent *client = (EncoreGuiXClientMessageEvent *)event_storage;
            if (client->format == 32 && (EncoreGuiAtom)client->data.l[0] == state->wm_delete) {
                state->open = false;
            }
        }
    }

    return state->open;
}

bool encore_gui_window_clear(size_t handle, uint32_t color_rgb) {
    EncoreGuiWindow *state = encore_gui_window_from_handle(handle);
    if (state == NULL || !state->open) {
        return false;
    }

    g_gui_x11.XSetForeground(state->display, state->gc, (unsigned long)color_rgb);
    g_gui_x11.XFillRectangle(state->display, state->window, state->gc, 0, 0, state->width, state->height);
    return true;
}

bool encore_gui_window_fill_rect(size_t handle, int32_t x, int32_t y, uint32_t width, uint32_t height, uint32_t color_rgb) {
    EncoreGuiWindow *state = encore_gui_window_from_handle(handle);
    if (state == NULL || !state->open || width == 0 || height == 0) {
        return false;
    }

    g_gui_x11.XSetForeground(state->display, state->gc, (unsigned long)color_rgb);
    g_gui_x11.XFillRectangle(state->display, state->window, state->gc, x, y, width, height);
    return true;
}

bool encore_gui_window_present(size_t handle) {
    EncoreGuiWindow *state = encore_gui_window_from_handle(handle);
    if (state == NULL || !state->open) {
        return false;
    }
    g_gui_x11.XFlush(state->display);
    return true;
}

bool encore_gui_window_destroy(size_t handle) {
    EncoreGuiWindow *state = encore_gui_window_from_handle(handle);
    if (state == NULL) {
        return false;
    }

    if (state->display != NULL) {
        if (state->gc != NULL) {
            g_gui_x11.XFreeGC(state->display, state->gc);
        }
        if (state->window != 0) {
            g_gui_x11.XDestroyWindow(state->display, state->window);
        }
        g_gui_x11.XCloseDisplay(state->display);
    }

    free(state);
    return true;
}
#else
size_t encore_gui_window_create(encore_str title, uint32_t width, uint32_t height) {
    (void)title;
    (void)width;
    (void)height;
    return 0;
}

bool encore_gui_window_is_open(size_t handle) {
    (void)handle;
    return false;
}

bool encore_gui_window_poll(size_t handle) {
    (void)handle;
    return false;
}

bool encore_gui_window_clear(size_t handle, uint32_t color_rgb) {
    (void)handle;
    (void)color_rgb;
    return false;
}

bool encore_gui_window_fill_rect(size_t handle, int32_t x, int32_t y, uint32_t width, uint32_t height, uint32_t color_rgb) {
    (void)handle;
    (void)x;
    (void)y;
    (void)width;
    (void)height;
    (void)color_rgb;
    return false;
}

bool encore_gui_window_present(size_t handle) {
    (void)handle;
    return false;
}

bool encore_gui_window_destroy(size_t handle) {
    (void)handle;
    return false;
}
#endif
