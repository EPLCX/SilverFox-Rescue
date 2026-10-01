ByteAddressBuffer InputBytes : register(t0);
RWStructuredBuffer<uint> ChunkHistograms : register(u0);
cbuffer ScanParameters : register(b0) { uint ByteLength; uint ChunkCount; uint Padding0; uint Padding1; };
groupshared uint LocalHistogram[256];
uint ReadByte(uint at){uint packed=InputBytes.Load(at&~3u);return(packed>>((at&3u)*8u))&255u;}
[numthreads(256,1,1)]
void main(uint3 group_id:SV_GroupID,uint group_index:SV_GroupIndex){
    LocalHistogram[group_index]=0u;GroupMemoryBarrierWithGroupSync();
    uint start=group_id.x*65536u;uint end=min(start+65536u,ByteLength);
    for(uint at=start+group_index;at<end;at+=256u){uint value=ReadByte(at);InterlockedAdd(LocalHistogram[value],1u);}
    GroupMemoryBarrierWithGroupSync();
    if(group_id.x<ChunkCount)ChunkHistograms[group_id.x*256u+group_index]=LocalHistogram[group_index];
}
