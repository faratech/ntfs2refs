/* Original host-I/O contract checks. Only fresh 1 MiB ordinary files. */
#include "strict_image.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
static const WCHAR zero_pin[]=L"30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58";
static int fresh(const WCHAR *root,unsigned case_id,WCHAR image[32768],WCHAR trace[32768]) {
    WCHAR directory[32768];HANDLE file;DWORD done;UCHAR *zero=(UCHAR*)calloc(1,N2R_IO_MAX);int ok=0;
    if(!zero)return 0;
    swprintf_s(directory,32768,L"%s\\case-%u",root,case_id);
    if(!CreateDirectoryW(directory,NULL))goto end;
    swprintf_s(image,32768,L"%s\\refs.adopt-test.raw",directory);swprintf_s(trace,32768,L"%s\\io.jsonl",directory);
    file=CreateFileW(image,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file==INVALID_HANDLE_VALUE)goto end;
    ok=WriteFile(file,zero,N2R_IO_MAX,&done,NULL)&&done==N2R_IO_MAX&&FlushFileBuffers(file);CloseHandle(file);
end: free(zero);return ok;
}
static int open_case(const WCHAR *root,unsigned id,WCHAR image[32768],WCHAR trace[32768]) {
    UCHAR pin[32];return N2rHex(zero_pin,pin)&&fresh(root,id,image,trace)
        &&N2rOpen(image,trace,N2R_IO_MAX,4096,4096,pin);
}
#define REQUIRE(expression) do {if(!(expression)){fprintf(stderr,"contract failure at line %d: %s\n",__LINE__,#expression);N2rClose();return 1;}}while(0)
int wmain(int argc,WCHAR **argv) {
    WCHAR image[32768],trace[32768];UCHAR bytes[1024],readback[1024],pin[32];HANDLE other;LARGE_INTEGER position;
    if(argc!=2){fwprintf(stderr,L"usage: backend-contract NEW_DIRECTORY\n");return 2;}
    REQUIRE(CreateDirectoryW(argv[1],NULL));
    REQUIRE(open_case(argv[1],1,image,trace));
    other=CreateFileW(image,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    REQUIRE(other==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_SHARING_VIOLATION);
    memset(bytes,0x5a,sizeof(bytes));N2rImage.writes_enabled=1;
    REQUIRE(N2rWrite(8192,512,bytes));REQUIRE(N2rFlush());
    REQUIRE(N2rImage.writes==1&&N2rImage.flushes==1&&!N2rImage.blocked_payload_writes);
    REQUIRE(N2rRead(8192,512,readback)&&!memcmp(bytes,readback,512));N2rClose();
    other=CreateFileW(image,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);REQUIRE(other!=INVALID_HANDLE_VALUE);
    position.QuadPart=8192;REQUIRE(SetFilePointerEx(other,position,NULL,FILE_BEGIN));
    {DWORD done=0;REQUIRE(ReadFile(other,readback,512,&done,NULL)&&done==512&&!memcmp(bytes,readback,512));}CloseHandle(other);
    REQUIRE(open_case(argv[1],2,image,trace));N2rImage.writes_enabled=1;
    REQUIRE(!N2rWrite(4096,512,bytes)&&N2rImage.blocked_payload_writes==1&&N2rImage.writes==0);
    REQUIRE(N2rRead(4096,512,readback));memset(bytes,0,512);REQUIRE(!memcmp(bytes,readback,512));N2rClose();
    REQUIRE(open_case(argv[1],3,image,trace));memset(readback,0xa5,sizeof(readback));
    REQUIRE(!N2rRead(N2R_IO_MAX-256,512,readback)&&readback[0]==0xa5&&N2rImage.poisoned);N2rClose();
    REQUIRE(open_case(argv[1],4,image,trace));position.QuadPart=512;
    REQUIRE(SetFilePointerEx(N2rImage.image,position,NULL,FILE_BEGIN)&&SetEndOfFile(N2rImage.image));
    memset(readback,0xa5,sizeof(readback));REQUIRE(!N2rRead(0,1024,readback)&&readback[512]==0xa5&&N2rImage.poisoned);N2rClose();
    REQUIRE(open_case(argv[1],5,image,trace));position.QuadPart=N2R_IO_MAX-512;
    REQUIRE(SetFilePointerEx(N2rImage.image,position,NULL,FILE_BEGIN)&&SetEndOfFile(N2rImage.image));
    REQUIRE(!N2rIdentity()&&N2rImage.poisoned);N2rImage.writes_enabled=1;REQUIRE(!N2rWrite(8192,512,bytes));N2rClose();
    REQUIRE(fresh(argv[1],6,image,trace)&&N2rHex(zero_pin,pin));pin[0]^=1;
    REQUIRE(!N2rOpen(image,trace,N2R_IO_MAX,4096,4096,pin)&&N2rImage.writes==0);N2rClose();
    puts("{\"kind\":\"strict-image-backend-contract\",\"success\":true,\"cases\":6,\"vm_operations\":false,\"refs_engine_operations\":false}");return 0;
}
