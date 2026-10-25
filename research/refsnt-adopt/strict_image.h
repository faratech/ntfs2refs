/* Original ntfs2refs research I/O adapter; not part of the Cargo product. */
#ifndef N2R_STRICT_IMAGE_H
#define N2R_STRICT_IMAGE_H
#include <windows.h>
#define N2R_IO_MAX (1024u * 1024u)
typedef struct {
    HANDLE image, trace;
    FILE_ID_INFO identity;
    ULONGLONG size, payload_offset, payload_length;
    ULONGLONG writes, written_bytes, flushes, blocked_payload_writes, sequence;
    int poisoned, writes_enabled;
} N2R_STRICT_IMAGE;
extern N2R_STRICT_IMAGE N2rImage;
int N2rOpen(const WCHAR *image, const WCHAR *trace, ULONGLONG size,
            ULONGLONG payload_offset, ULONGLONG payload_length, const UCHAR expected_image[32]);
int N2rRead(ULONGLONG offset, ULONG length, PVOID output);
int N2rWrite(ULONGLONG offset, ULONG length, const VOID *input);
int N2rFlush(void);
int N2rIdentity(void);
int N2rHashRange(ULONGLONG offset, ULONGLONG length, UCHAR digest[32]);
int N2rHex(const WCHAR *text, UCHAR digest[32]);
void N2rHexOut(const UCHAR digest[32], CHAR text[65]);
void N2rClose(void);
#endif
