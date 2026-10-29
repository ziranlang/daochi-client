#include "record_codec.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char input[65536], packed[65536], opened[65536];
    memset(input, 'x', sizeof input);
    input[0]='{'; input[sizeof input-1]='}';
    Slice source={.data=input,.length=sizeof input};
    Slice encoded={.data=packed,.length=sizeof packed};
    Slice decoded={.data=opened,.length=sizeof opened};
    int64_t count=record_codec_PackRecord(source,encoded);
    assert(count>12 && count<sizeof input/10);
    encoded.length=count;
    assert(record_codec_RecordIsPacked(encoded));
    assert(record_codec_PackedRecordSize(encoded,sizeof input)==sizeof input);
    assert(record_codec_UnpackRecord(encoded,decoded,sizeof input)==sizeof input);
    assert(memcmp(input,opened,sizeof input)==0);
    assert(record_codec_UnpackRecord(encoded,decoded,sizeof input-1)==-1);
    decoded.length=sizeof opened-1;
    assert(record_codec_UnpackRecord(encoded,decoded,sizeof input)==-1);
    decoded.length=sizeof opened;
    ((unsigned char*)packed)[8]=255; ((unsigned char*)packed)[9]=255;
    ((unsigned char*)packed)[10]=255; ((unsigned char*)packed)[11]=255;
    assert(record_codec_PackedRecordSize(encoded,8388608)==-1);
    source.length=sizeof input;
    count=record_codec_PackRecord(source,(Slice){.data=packed,.length=sizeof packed});
    encoded.length=count;
    packed[count-1]^=1;
    assert(record_codec_UnpackRecord(encoded,decoded,sizeof input)==-1);
    source.length=2;
    assert(record_codec_PackRecord(source,(Slice){.data=packed,.length=sizeof packed})==0);
    memset(input,'x',sizeof input);
    assert(record_codec_PackRecord(source,(Slice){.data=packed,.length=sizeof packed})==0);
    puts("Packed records: bounded gzip, independent buffers, framing and corruption rejection passed");
    return 0;
}
