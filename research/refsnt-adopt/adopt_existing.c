/* Original experiment driver for the external pinned REFSNT API. */
#include "rfseng.h"
#include "strict_image.h"
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#pragma comment(lib,"bcrypt.lib")
#define UPSTREAM "bdde6875b47a7370f5f98dd1d6b1a3e19278ca2a"
static RFS_VOL volume;
RFS_STATUS RfsHostRead(PRFS_VOL v,ULONGLONG offset,ULONG length,PVOID output){(void)v;return N2rRead(offset,length,output)?RFS_OK:RFS_IO_ERROR;}
RFS_STATUS RfsHostWrite(PRFS_VOL v,ULONGLONG offset,ULONG length,const VOID *input){(void)v;return N2rWrite(offset,length,input)?RFS_OK:RFS_IO_ERROR;}
RFS_STATUS RfsHostFlush(PRFS_VOL v){(void)v;return N2rFlush()?RFS_OK:RFS_IO_ERROR;}
PVOID RfsHostAlloc(ULONG length){return malloc(length?length:1);}
VOID RfsHostFree(PVOID pointer){free(pointer);}
ULONGLONG RfsHostNowNt(VOID){FILETIME now;GetSystemTimeAsFileTime(&now);return ((ULONGLONG)now.dwHighDateTime<<32)|now.dwLowDateTime;}

static int number(const WCHAR *text,ULONGLONG *value){WCHAR *end;*value=wcstoull(text,&end,0);return *text&&!*end&&*text!=L'-';}
static RFS_STATUS verify_file(PRFS_FILE file,ULONGLONG physical,ULONG clusters,UCHAR digest[32]) {
    BCRYPT_ALG_HANDLE algorithm=NULL;BCRYPT_HASH_HANDLE hash=NULL;UCHAR *bytes=NULL;RFS_STATUS status=RFS_IO_ERROR;
    ULONGLONG offset=0,vcn=0,total=(ULONGLONG)clusters*4096;
    if(file->Size!=total||file->ValidSize!=total||file->Alloc!=total||file->Inline)return RFS_CORRUPT;
    while(vcn<clusters){ULONGLONG actual=0;ULONG run=0;status=RfsFileMap(&volume,file,vcn,&actual,&run);
        if(!RFS_SUCCESS(status)||actual!=physical+vcn||!run)return RFS_CORRUPT;vcn+=run>clusters-vcn?clusters-vcn:run;}
    bytes=(UCHAR*)malloc(N2R_IO_MAX);if(!bytes)return RFS_NO_MEMORY;
    if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0)<0
        ||BCryptCreateHash(algorithm,&hash,NULL,0,NULL,0,0)<0)goto done;
    while(offset<total){ULONG wanted=(ULONG)(total-offset>N2R_IO_MAX?N2R_IO_MAX:total-offset),got=0;
        status=RfsFileRead(&volume,file,offset,wanted,bytes,&got);
        if(!RFS_SUCCESS(status)||got!=wanted||BCryptHashData(hash,bytes,got,0)<0){status=RFS_IO_ERROR;goto done;}offset+=got;}
    status=BCryptFinishHash(hash,digest,32,0)>=0?RFS_OK:RFS_IO_ERROR;
done: if(hash)BCryptDestroyHash(hash);if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);free(bytes);return status;
}

int wmain(int argc,WCHAR **argv) {
    ULONGLONG image_bytes=0,physical=0,count=0,reserved=0,virtual_lcn=0;ULONG got=0;
    UCHAR expected_image[32]={0},expected_payload[32]={0},before[32]={0},after[32]={0},logical[32]={0},boot[512];
    CHAR before_hex[65],after_hex[65],logical_hex[65],result[2048];HANDLE output=INVALID_HANDLE_VALUE;DWORD written;
    const USHORT name[]={ 'a','d','o','p','t','e','d','-','e','x','i','s','t','i','n','g','.','b','i','n' };
    RFS_DIRENT entry;PRFS_FILE file=NULL;RFS_STATUS status=RFS_INVALID;const CHAR *stage="arguments";
    int mounted=0,success=0,exact=0,reopened=0;
    if(argc!=9){fwprintf(stderr,L"usage: adopt-existing refs.adopt-test.raw BYTES IMAGE_SHA256 PLCN CLUSTERS PAYLOAD_SHA256 TRACE.jsonl RESULT.json\n");return 2;}
    if(!number(argv[2],&image_bytes)||!number(argv[4],&physical)||!number(argv[5],&count)||!count||count>65536
        ||physical<64||physical>image_bytes/4096||count>image_bytes/4096-physical
        ||!N2rHex(argv[3],expected_image)||!N2rHex(argv[6],expected_payload))goto done;
    stage="strict-image-open";
    if(!N2rOpen(argv[1],argv[7],image_bytes,physical*4096,count*4096,expected_image))goto done;
    stage="payload-pin";if(!N2rHashRange(physical*4096,count*4096,before)||memcmp(before,expected_payload,32))goto done;
    if(!N2rRead(0,512,boot)||memcmp(boot+3,"ReFS",4)||memcmp(boot+16,"FSRS",4)||boot[40]!=3||boot[41]!=14)goto done;
    volume.DeviceBytes=image_bytes;volume.SectorSize=512;stage="engine-mount";
    status=RfsMount(&volume,FALSE);if(!RFS_SUCCESS(status))goto done;mounted=1;
    if(volume.ReadOnly||volume.ClusterSize!=4096||volume.Major!=3||volume.Minor!=14){status=RFS_NOT_SUPPORTED;goto done;}
    N2rImage.writes_enabled=1;stage="exact-allocator-reservation";
    status=RfsAllocIn(&volume,physical,physical+count,(ULONG)count,(ULONG)count,1,&reserved,&got);
    if(!RFS_SUCCESS(status))goto done;
    if(reserved!=physical||got!=count){status=RFS_CORRUPT;goto done;}exact=1;
    status=RfsToVirtual(&volume,physical,&virtual_lcn);if(!RFS_SUCCESS(status))goto done;
    stage="virtual-contiguity";
    {ULONGLONG i;for(i=0;i<count;i++){ULONGLONG next=0;status=RfsToVirtual(&volume,physical+i,&next);
        if(!RFS_SUCCESS(status)||virtual_lcn>~(ULONGLONG)0-i||next!=virtual_lcn+i){status=RFS_NOT_SUPPORTED;goto done;}}}
    stage="empty-file-create";status=RfsCreate(&volume,REFS_OID_ROOT,name,sizeof(name)/sizeof(name[0]),FALSE,0x20,&entry);
    if(!RFS_SUCCESS(status))goto done;
    status=RfsFileOpen(&volume,REFS_OID_ROOT,&entry,&file);if(!RFS_SUCCESS(status))goto done;
    stage="file-adopt";status=RfsFileAdopt(&volume,file,virtual_lcn,(ULONG)count);if(!RFS_SUCCESS(status))goto done;
    RfsFileClose(file);file=NULL;stage="durable-commit";status=RfsCommit(&volume);
    if(!RFS_SUCCESS(status)||!N2rFlush())goto done;
    RfsUnmount(&volume);mounted=0;memset(&volume,0,sizeof(volume));N2rImage.writes_enabled=0;
    volume.DeviceBytes=image_bytes;volume.SectorSize=512;stage="disk-reopen";status=RfsMount(&volume,TRUE);
    if(!RFS_SUCCESS(status))goto done;mounted=1;reopened=1;
    status=RfsDirLookup(&volume,REFS_OID_ROOT,name,sizeof(name)/sizeof(name[0]),&entry);if(!RFS_SUCCESS(status))goto done;
    status=RfsFileOpen(&volume,REFS_OID_ROOT,&entry,&file);if(!RFS_SUCCESS(status))goto done;
    stage="mapping-and-logical-read";status=verify_file(file,physical,(ULONG)count,logical);if(!RFS_SUCCESS(status))goto done;
    stage="payload-after";if(!N2rHashRange(physical*4096,count*4096,after)||memcmp(after,before,32)||memcmp(logical,before,32)
        ||!N2rIdentity()||N2rImage.blocked_payload_writes||N2rImage.poisoned)goto done;
    success=1;stage="complete";
done:
    if(file)RfsFileClose(file);if(mounted)RfsUnmount(&volume);
    N2rHexOut(before,before_hex);N2rHexOut(after,after_hex);N2rHexOut(logical,logical_hex);
    sprintf_s(result,sizeof(result),"{\"schema_version\":1,\"kind\":\"strict-refsnt-existing-extent-adoption\",\"upstream_commit\":\"%s\",\"success\":%s,\"stage\":\"%s\",\"engine_status\":%lu,\"requested_plcn\":%llu,\"returned_plcn\":%llu,\"requested_clusters\":%llu,\"returned_clusters\":%lu,\"vlcn\":%llu,\"exact_reservation\":%s,\"reopened_read_only\":%s,\"metadata_writes\":%llu,\"written_bytes\":%llu,\"real_image_flushes\":%llu,\"blocked_payload_writes\":%llu,\"payload_before_sha256\":\"%s\",\"payload_after_sha256\":\"%s\",\"logical_sha256\":\"%s\",\"native_windows_qualified\":false}\n",
        UPSTREAM,success?"true":"false",stage,(ULONG)status,physical,reserved,count,got,virtual_lcn,exact?"true":"false",reopened?"true":"false",
        N2rImage.writes,N2rImage.written_bytes,N2rImage.flushes,N2rImage.blocked_payload_writes,before_hex,after_hex,logical_hex);
    output=CreateFileW(argv[8],GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,NULL);
    if(output==INVALID_HANDLE_VALUE||!WriteFile(output,result,(DWORD)strlen(result),&written,NULL)||written!=strlen(result)||!FlushFileBuffers(output))success=0;
    if(output!=INVALID_HANDLE_VALUE)CloseHandle(output);N2rClose();fputs(result,stdout);return success?0:1;
}
