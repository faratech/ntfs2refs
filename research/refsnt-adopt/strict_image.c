/* Original strict regular-image backend for the pinned GPL engine experiment.
 * No upstream REFSNT implementation is copied here. See README.md. */
#include "strict_image.h"
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#pragma comment(lib,"bcrypt.lib")

N2R_STRICT_IMAGE N2rImage;
static int fail(const char *message) {
    fprintf(stderr,"strict image: %s (Win32 %lu)\n",message,GetLastError());
    N2rImage.poisoned=1;return 0;
}
static int seek_to(HANDLE handle,ULONGLONG offset) {
    LARGE_INTEGER position;if(offset>0x7fffffffffffffffULL)return 0;
    position.QuadPart=(LONGLONG)offset;return SetFilePointerEx(handle,position,NULL,FILE_BEGIN)!=0;
}
static int read_exact(HANDLE handle,ULONGLONG offset,PVOID output,ULONG length) {
    DWORD done=0;return seek_to(handle,offset)&&ReadFile(handle,output,length,&done,NULL)&&done==length;
}
static int write_exact(HANDLE handle,const VOID *input,ULONG length) {
    DWORD done=0;return WriteFile(handle,input,length,&done,NULL)&&done==length;
}
static int bounded(ULONGLONG offset,ULONGLONG length) {
    return length && offset<=N2rImage.size && length<=N2rImage.size-offset;
}
static int trace_line(const CHAR *line) {
    size_t length=strlen(line);
    if(!N2rImage.trace || length>1024 || !write_exact(N2rImage.trace,line,(ULONG)length)
        ||!FlushFileBuffers(N2rImage.trace))return fail("durable trace append failed");
    return 1;
}
void N2rHexOut(const UCHAR digest[32],CHAR text[65]) {
    static const CHAR hex[]="0123456789abcdef";ULONG i;
    for(i=0;i<32;i++){text[2*i]=hex[digest[i]>>4];text[2*i+1]=hex[digest[i]&15];}text[64]=0;
}
int N2rHex(const WCHAR *text,UCHAR digest[32]) {
    ULONG i;if(wcslen(text)!=64)return 0;
    for(i=0;i<32;i++){ULONG j;UCHAR value=0;for(j=0;j<2;j++){WCHAR c=text[2*i+j];
        if(c>='0'&&c<='9')c-=L'0';else if(c>='a'&&c<='f')c=c-L'a'+10;
        else if(c>='A'&&c<='F')c=c-L'A'+10;else return 0;value=(UCHAR)((value<<4)|c);}digest[i]=value;}return 1;
}
static int hash_start(BCRYPT_ALG_HANDLE *algorithm,BCRYPT_HASH_HANDLE *hash) {
    return BCryptOpenAlgorithmProvider(algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0)>=0
        && BCryptCreateHash(*algorithm,hash,NULL,0,NULL,0,0)>=0;
}
static int hash_bytes(const VOID *bytes,ULONG length,UCHAR digest[32]) {
    BCRYPT_ALG_HANDLE algorithm=NULL;BCRYPT_HASH_HANDLE hash=NULL;int ok=0;
    if(hash_start(&algorithm,&hash)&&BCryptHashData(hash,(PUCHAR)bytes,length,0)>=0
        &&BCryptFinishHash(hash,digest,32,0)>=0)ok=1;
    if(hash)BCryptDestroyHash(hash);if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);return ok;
}
int N2rIdentity(void) {
    LARGE_INTEGER length;FILE_ID_INFO identity;FILE_STANDARD_INFO standard;FILE_ATTRIBUTE_TAG_INFO tag;
    if(!GetFileSizeEx(N2rImage.image,&length)||length.QuadPart<0||(ULONGLONG)length.QuadPart!=N2rImage.size
        ||!GetFileInformationByHandleEx(N2rImage.image,FileIdInfo,&identity,sizeof(identity))
        ||memcmp(&identity,&N2rImage.identity,sizeof(identity))
        ||!GetFileInformationByHandleEx(N2rImage.image,FileStandardInfo,&standard,sizeof(standard))
        ||standard.Directory||standard.DeletePending||standard.NumberOfLinks!=1
        ||!GetFileInformationByHandleEx(N2rImage.image,FileAttributeTagInfo,&tag,sizeof(tag))
        ||(tag.FileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_COMPRESSED|FILE_ATTRIBUTE_ENCRYPTED)))
        return fail("regular-image identity/length/type changed");
    return 1;
}
int N2rRead(ULONGLONG offset,ULONG length,PVOID output) {
    if(length>N2R_IO_MAX||!bounded(offset,length)||!read_exact(N2rImage.image,offset,output,length))
        return fail("short, failed or out-of-bounds read");return 1;
}
int N2rHashRange(ULONGLONG offset,ULONGLONG length,UCHAR digest[32]) {
    BCRYPT_ALG_HANDLE algorithm=NULL;BCRYPT_HASH_HANDLE hash=NULL;UCHAR *buffer=NULL;int ok=0;
    if(!bounded(offset,length)||!hash_start(&algorithm,&hash))goto done;
    buffer=(UCHAR*)malloc(N2R_IO_MAX);if(!buffer)goto done;
    while(length){ULONG count=(ULONG)(length>N2R_IO_MAX?N2R_IO_MAX:length);
        if(!N2rRead(offset,count,buffer)||BCryptHashData(hash,buffer,count,0)<0)goto done;
        offset+=count;length-=count;}
    if(BCryptFinishHash(hash,digest,32,0)>=0)ok=1;
done: if(buffer)free(buffer);if(hash)BCryptDestroyHash(hash);if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);
    return ok?1:fail("range hash failed");
}
int N2rWrite(ULONGLONG offset,ULONG length,const VOID *input) {
    UCHAR *before=NULL,*after=NULL,old_hash[32],new_hash[32];CHAR old_hex[65],new_hex[65],line[512];int ok=0;
    if(N2rImage.poisoned||!N2rImage.writes_enabled||length>N2R_IO_MAX||!bounded(offset,length)
        ||offset%512||length%512||N2rImage.writes>=8192||N2rImage.written_bytes+length>256ULL*1024*1024)
        return fail("write state, bounds, alignment or budget refused");
    if(offset<N2rImage.payload_offset+N2rImage.payload_length && N2rImage.payload_offset<offset+length){
        N2rImage.blocked_payload_writes++;return fail("write overlaps protected existing payload");}
    if(!N2rIdentity())return 0;
    before=(UCHAR*)malloc(length);after=(UCHAR*)malloc(length);if(!before||!after)goto done;
    if(!N2rRead(offset,length,before)||!hash_bytes(before,length,old_hash)||!hash_bytes(input,length,new_hash))goto done;
    N2rHexOut(old_hash,old_hex);N2rHexOut(new_hash,new_hex);
    sprintf_s(line,sizeof(line),"{\"op\":\"write-intent\",\"seq\":%llu,\"offset\":%llu,\"length\":%lu,\"old_sha256\":\"%s\",\"new_sha256\":\"%s\"}\n",
        ++N2rImage.sequence,offset,length,old_hex,new_hex);
    if(!trace_line(line)||!seek_to(N2rImage.image,offset)||!write_exact(N2rImage.image,input,length))goto done;
    if(!read_exact(N2rImage.image,offset,after,length)||memcmp(after,input,length))goto done;
    N2rImage.writes++;N2rImage.written_bytes+=length;
    sprintf_s(line,sizeof(line),"{\"op\":\"write-readback\",\"seq\":%llu,\"offset\":%llu,\"length\":%lu}\n",++N2rImage.sequence,offset,length);
    if(!trace_line(line))goto done;ok=1;
done: if(before)free(before);if(after)free(after);return ok?1:fail("write/trace/readback failed");
}
int N2rFlush(void) {
    CHAR line[256];if(N2rImage.poisoned||!N2rIdentity()||!FlushFileBuffers(N2rImage.image))return fail("image flush failed");
    N2rImage.flushes++;
    sprintf_s(line,sizeof(line),"{\"op\":\"image-flush-complete\",\"seq\":%llu,\"writes\":%llu,\"written_bytes\":%llu}\n",
        ++N2rImage.sequence,N2rImage.writes,N2rImage.written_bytes);
    return trace_line(line);
}
int N2rOpen(const WCHAR *image,const WCHAR *trace,ULONGLONG size,ULONGLONG offset,ULONGLONG length,const UCHAR expected[32]) {
    LARGE_INTEGER actual;WCHAR final_path[32768];DWORD count;UCHAR digest[32];CHAR line[512];size_t n=wcslen(image);
    memset(&N2rImage,0,sizeof(N2rImage));N2rImage.image=INVALID_HANDLE_VALUE;
    if(n<19||_wcsicmp(image+n-19,L"refs.adopt-test.raw")||size<1024*1024||size>128ULL*1024*1024*1024
        ||offset%4096||length%4096||offset>size||!length||length>size-offset||length>256ULL*1024*1024
        ||!wcsncmp(image,L"\\\\.\\",4)||!wcsncmp(image,L"\\\\?\\Volume{",11))return fail("disposable regular raw-image path/geometry required");
    N2rImage.size=size;N2rImage.payload_offset=offset;N2rImage.payload_length=length;
    N2rImage.image=CreateFileW(image,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,NULL);
    if(N2rImage.image==INVALID_HANDLE_VALUE||GetFileType(N2rImage.image)!=FILE_TYPE_DISK
        ||!GetFileSizeEx(N2rImage.image,&actual)||(ULONGLONG)actual.QuadPart!=size
        ||!GetFileInformationByHandleEx(N2rImage.image,FileIdInfo,&N2rImage.identity,sizeof(N2rImage.identity)))return fail("exclusive image open/identity failed");
    count=GetFinalPathNameByHandleW(N2rImage.image,final_path,32768,VOLUME_NAME_GUID);
    if(!count||count>=32768||wcsncmp(final_path,L"\\\\?\\Volume{",11)||!N2rIdentity())return fail("local regular volume-GUID image required");
    if(!N2rHashRange(0,size,digest)||memcmp(digest,expected,32))return fail("full input image SHA-256 differs");
    N2rImage.trace=CreateFileW(trace,GENERIC_READ|GENERIC_WRITE,0,NULL,CREATE_NEW,
        FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,NULL);
    if(N2rImage.trace==INVALID_HANDLE_VALUE){N2rImage.trace=NULL;return fail("fresh external trace required");}
    sprintf_s(line,sizeof(line),"{\"format\":\"n2r-refsnt-strict-io-v1\",\"image_bytes\":%llu,\"protected_offset\":%llu,\"protected_length\":%llu}\n",size,offset,length);
    return trace_line(line);
}
void N2rClose(void) {
    if(N2rImage.trace&&N2rImage.trace!=INVALID_HANDLE_VALUE)CloseHandle(N2rImage.trace);
    if(N2rImage.image&&N2rImage.image!=INVALID_HANDLE_VALUE)CloseHandle(N2rImage.image);
    N2rImage.trace=NULL;N2rImage.image=NULL;
}
