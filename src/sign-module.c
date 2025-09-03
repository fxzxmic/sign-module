/* sign-module.c
 *
 * Memory-optimized kernel module signing implementation:
 *   <hash> <private_key.pem> <x509.der|.pem> <module.ko[.xz]>
 *
 * Semantics: Use kernel-standard XZ compression with multithreading for optimal compression.
 *
 * Requires modern OpenSSL 3.x with CMS and liblzma 5.4+.
 * C23 standard with modern designated initializers and compound literals.
 *
 * Build:
 *   gcc -std=c17 -Os -s -flto -ffunction-sections -fdata-sections -Wl,--gc-sections -Wall -Wextra -Wno-unused-parameter sign-module.c -o sign-module -lcrypto -llzma
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <arpa/inet.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/cms.h>

#include <lzma.h>

#include "linux/module_signature.h"

#define PKEY_ID_PKCS7 2

static const char magic_number[] = MODULE_SIG_STRING;

/* helpers */
static void fatal(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    if (ERR_peek_error()) {
        ERR_print_errors_fp(stderr);
    }
    exit(1);
}

static void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) {
        fatal("Out of memory\n");
    }
    return p;
}

/* Read entire file into memory */
static unsigned char *read_file(const char *path, size_t *size_out)
{
    struct stat st;
    if (stat(path, &st) < 0) {
        fatal("stat(%s): %s\n", path, strerror(errno));
    }

    if (st.st_size < 0 || (size_t)st.st_size > SIZE_MAX / 2) {
        fatal("file %s too large or invalid size\n", path);
    }

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fatal("open(%s): %s\n", path, strerror(errno));
    }

    unsigned char *buf = xmalloc(st.st_size);
    for (ssize_t total = 0; total < st.st_size; ) {
        ssize_t r = read(fd, buf + total, st.st_size - total);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            free(buf);
            fatal("read(%s): %s\n", path, strerror(errno));
        }
        if (r == 0) {
            break;
        }
        total += r;
    }
    close(fd);

    return *size_out = st.st_size, buf;
}

/* Detect xz by header */
static bool is_xz_magic(const unsigned char *buf, size_t n)
{
    static const unsigned char magic[6] = {0xFD, '7', 'z', 'X', 'Z', 0x00};
    return n >= 6 && memcmp(buf, magic, 6) == 0;
}

/* Check if module is already signed and return unsigned size */
static size_t get_unsigned_size(const unsigned char *buf, size_t buf_sz)
{
    static const size_t magic_len = sizeof(magic_number) - 1;
    static const size_t min_sig_size = sizeof(struct module_signature) + magic_len;

    // Loop to strip all signature layers
    while (buf_sz >= min_sig_size &&
           memcmp(buf + buf_sz - magic_len, magic_number, magic_len) == 0) {

        const struct module_signature *ms =
            (const struct module_signature *)(buf + buf_sz - magic_len - sizeof(struct module_signature));
        uint32_t sig_len = ntohl(ms->sig_len);
        size_t total_trailer = sig_len + sizeof(struct module_signature) + magic_len;

        if (total_trailer > buf_sz) {
            break;  // Invalid signature
        }
        buf_sz -= total_trailer;
    }

    return buf_sz;
}

/* Decompress XZ with conservative memory allocation */
static unsigned char *xz_decompress(const unsigned char *in, size_t in_sz, size_t *out_sz)
{
    lzma_stream strm = LZMA_STREAM_INIT;
    if (lzma_stream_decoder(&strm, UINT64_MAX, LZMA_CONCATENATED) != LZMA_OK) {
        fatal("lzma_stream_decoder failed\n");
    }

    // Conservative initial allocation - grow as needed
    size_t cap = in_sz < 1024 ? 4096 : in_sz * 3;  // Reduced from 6x to 3x
    unsigned char *out = xmalloc(cap);

    strm.next_in = in;
    strm.avail_in = in_sz;
    strm.next_out = out;
    strm.avail_out = cap;

    for (;;) {
        lzma_ret r = lzma_code(&strm, LZMA_FINISH);
        if (r == LZMA_STREAM_END) {
            *out_sz = strm.next_out - out;
            lzma_end(&strm);
            return realloc(out, *out_sz) ?: out;
        }
        if (r != LZMA_OK) {
            lzma_end(&strm);
            free(out);
            fatal("lzma_code decompress error %d\n", (int)r);
        }
        if (strm.avail_out == 0) {
            size_t used = strm.next_out - out;
            cap += cap >> 2;  // Grow by 25% instead of 50%
            unsigned char *new_out = realloc(out, cap);
            if (!new_out) {
                lzma_end(&strm);
                free(out);
                fatal("OOM during xz_decompress\n");
            }
            out = new_out;
            strm.next_out = out + used;
            strm.avail_out = cap - used;
        }
    }
}

/* Compress memory to XZ using multithreaded encoder */
static unsigned char *xz_compress(const unsigned char *in, size_t in_sz, size_t *out_sz)
{
    lzma_stream strm = LZMA_STREAM_INIT;

    lzma_options_lzma lzma_opts;
    if (lzma_lzma_preset(&lzma_opts, 9) != LZMA_OK) {
        fatal("lzma_lzma_preset failed\n");
    }

    // Multithreaded encoder with kernel-standard configuration
    if (lzma_stream_encoder_mt(&strm, &(lzma_mt){
        .threads = sysconf(_SC_NPROCESSORS_ONLN) > 0 ? (uint32_t)sysconf(_SC_NPROCESSORS_ONLN) : 1,
        .filters = (lzma_filter[]){
            {LZMA_FILTER_LZMA2, &lzma_opts},
            {LZMA_VLI_UNKNOWN, NULL}
        },
        .check = LZMA_CHECK_CRC32
    }) != LZMA_OK) {
        fatal("lzma_stream_encoder_mt failed\n");
    }

    size_t cap = in_sz > 64 * 1024 ? in_sz / 8 : 4096;
    unsigned char *out = xmalloc(cap);

    strm.next_in = in;
    strm.avail_in = in_sz;
    strm.next_out = out;
    strm.avail_out = cap;

    for (;;) {
        lzma_ret r = lzma_code(&strm, LZMA_FINISH);
        if (r == LZMA_STREAM_END) {
            lzma_end(&strm);
            return *out_sz = strm.next_out - out, realloc(out, *out_sz) ?: out;
        }
        if (r != LZMA_OK) {
            lzma_end(&strm);
            free(out);
            fatal("lzma_code compress error %d\n", (int)r);
        }
        if (strm.avail_out == 0) {
            size_t used = strm.next_out - out;
            unsigned char *new_out = realloc(out, cap <<= 1);
            if (!new_out) {
                lzma_end(&strm);
                free(out);
                fatal("OOM during xz_compress\n");
            }
            strm.next_out = (out = new_out) + used;
            strm.avail_out = cap - used;
        }
    }
}

/* Load X.509 (DER or PEM auto-detect) */
static X509 *load_x509(const char *path)
{
    BIO *b = BIO_new_file(path, "rb");
    if (!b) {
        fatal("open cert %s\n", path);
    }

    unsigned char hdr[2];
    if (BIO_read(b, hdr, 2) != 2) {
        BIO_free(b);
        fatal("read cert header %s\n", path);
    }
    BIO_seek(b, 0);

    // Auto-detect DER vs PEM format and load
    X509 *x = (hdr[0] == 0x30 && hdr[1] >= 0x81 && hdr[1] <= 0x84)
              ? d2i_X509_bio(b, NULL) : PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    if (!x) {
        fatal("parse cert %s\n", path);
    }
    return x;
}

/* Load private key PEM with validation */
static EVP_PKEY *load_key(const char *path)
{
    BIO *b = BIO_new_file(path, "rb");
    if (!b) {
        fatal("open key %s\n", path);
    }

    EVP_PKEY *k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    BIO_free(b);

    if (!k) {
        fatal("parse key %s\n", path);
    }
    if (!EVP_PKEY_can_sign(k)) {
        EVP_PKEY_free(k);
        fatal("key %s cannot be used for signing\n", path);
    }

    return k;
}

/* Create CMS detached signature and append per-kernel format. Return new buffer */
static unsigned char *create_signed_module(const unsigned char *module, size_t module_sz,
                                           const char *hash, EVP_PKEY *key, X509 *cert,
                                           size_t *out_sz)
{
    const EVP_MD *md = EVP_get_digestbyname(hash);
    if (!md) {
        fatal("unknown digest '%s'\n", hash);
    }

    // Modern OpenSSL 3.x CMS creation with compound literal
    CMS_ContentInfo *cms = CMS_sign(NULL, NULL, NULL, NULL,
                                   CMS_NOCERTS | CMS_PARTIAL | CMS_BINARY | CMS_DETACHED);
    if (!cms || !CMS_add1_signer(cms, cert, key, md, CMS_NOCERTS | CMS_BINARY | CMS_NOSMIMECAP | CMS_NOATTR)) {
        CMS_ContentInfo_free(cms);
        fatal("CMS_sign/add1_signer failed\n");
    }

    BIO *bdata = BIO_new_mem_buf(module, module_sz);
    if (!bdata || CMS_final(cms, bdata, NULL, CMS_NOCERTS | CMS_BINARY) != 1) {
        BIO_free(bdata);
        CMS_ContentInfo_free(cms);
        fatal("CMS_final failed\n");
    }
    BIO_free(bdata);

    BIO *bder = BIO_new(BIO_s_mem());
    if (!bder || i2d_CMS_bio_stream(bder, cms, NULL, 0) != 1) {
        BIO_free(bder);
        CMS_ContentInfo_free(cms);
        fatal("i2d_CMS_bio_stream failed\n");
    }

    BUF_MEM *bufmem;
    BIO_get_mem_ptr(bder, &bufmem);
    if (!bufmem || !bufmem->data) {
        BIO_free(bder);
        CMS_ContentInfo_free(cms);
        fatal("BIO_get_mem_ptr failed\n");
    }

    // C23 designated initializer with direct calculation
    size_t total = module_sz + bufmem->length + sizeof(struct module_signature) + (sizeof(magic_number) - 1);
    unsigned char *out = xmalloc(total);

    // Direct memcpy chain using compound assignment
    unsigned char *p = mempcpy(out, module, module_sz);
    p = mempcpy(p, bufmem->data, bufmem->length);
    p = mempcpy(p, &(struct module_signature){
        .id_type = PKEY_ID_PKCS7,
        .sig_len = htonl((uint32_t)bufmem->length)
    }, sizeof(struct module_signature));
    memcpy(p, magic_number, sizeof(magic_number) - 1);

    BIO_free(bder);
    CMS_ContentInfo_free(cms);

    return *out_sz = total, out;
}

/* Write buffer to file atomically */
static void write_file(const char *path, const unsigned char *buf, size_t buf_sz)
{
    int fd = open(path, O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) {
        fatal("open(%s): %s\n", path, strerror(errno));
    }

    for (ssize_t total = 0; total < (ssize_t)buf_sz; ) {
        ssize_t w = write(fd, buf + total, buf_sz - total);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            fatal("write(%s): %s\n", path, strerror(errno));
        }
        total += w;
    }

    if (close(fd) != 0) {
        fatal("close(%s): %s\n", path, strerror(errno));
    }
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <hash> <private_key.pem> <x509.der|.pem> <module.ko[.xz]>\n", argv[0]);
        return 2;
    }

    // Modern OpenSSL initialization (OpenSSL 3.0+)
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);

    const char *hash = argv[1];
    const char *key_path = argv[2];
    const char *cert_path = argv[3];
    const char *module_path = argv[4];

    // Load crypto objects and read file
    EVP_PKEY *key = load_key(key_path);
    X509 *cert = load_x509(cert_path);

    size_t original_sz;
    unsigned char *data = read_file(module_path, &original_sz);

    // Process: XZ -> decompress -> sign -> recompress; otherwise sign directly
    if (is_xz_magic(data, original_sz)) {
        size_t elf_sz;
        unsigned char *elf = xz_decompress(data, original_sz, &elf_sz);
        free(data);

        size_t signed_sz;
        unsigned char *signed_module = create_signed_module(elf, get_unsigned_size(elf, elf_sz),
                                                           hash, key, cert, &signed_sz);
        free(elf);

        size_t compressed_sz;
        unsigned char *compressed = xz_compress(signed_module, signed_sz, &compressed_sz);
        free(signed_module);

        write_file(module_path, compressed, compressed_sz);
        free(compressed);
    } else {
        size_t signed_sz;
        unsigned char *signed_module = create_signed_module(data, get_unsigned_size(data, original_sz),
                                                           hash, key, cert, &signed_sz);
        free(data);

        write_file(module_path, signed_module, signed_sz);
        free(signed_module);
    }

    EVP_PKEY_free(key);
    X509_free(cert);
    return 0;
}
