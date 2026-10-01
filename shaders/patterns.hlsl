ByteAddressBuffer InputBytes : register(t0);
ByteAddressBuffer PatternBytes : register(t1);
ByteAddressBuffer PatternMeta : register(t2);
RWStructuredBuffer<uint> PatternHits : register(u0);

cbuffer ScanParameters : register(b0)
{
    uint ByteLength;
    uint PatternCount;
    uint TotalThreads;
    uint Padding;
};

uint InputByte(uint index)
{
    uint packed = InputBytes.Load(index & ~3u);
    return (packed >> ((index & 3u) * 8u)) & 255u;
}

uint PatternByte(uint index)
{
    uint packed = PatternBytes.Load(index & ~3u);
    return (packed >> ((index & 3u) * 8u)) & 255u;
}

uint AsciiLower(uint value)
{
    return value >= 65u && value <= 90u ? value + 32u : value;
}

[numthreads(256, 1, 1)]
void main(uint3 dispatch_id : SV_DispatchThreadID)
{
    for (uint position = dispatch_id.x; position < ByteLength; position += TotalThreads)
    {
        for (uint pattern = 0u; pattern < PatternCount; ++pattern)
        {
            if (PatternHits[pattern] != 0u)
                continue;
            uint offset = PatternMeta.Load(pattern * 8u);
            uint length = PatternMeta.Load(pattern * 8u + 4u);
            if (length == 0u || position + length > ByteLength)
                continue;
            bool matched = true;
            for (uint index = 0u; index < length; ++index)
            {
                if (AsciiLower(InputByte(position + index)) != AsciiLower(PatternByte(offset + index)))
                {
                    matched = false;
                    break;
                }
            }
            if (matched)
            {
                uint previous;
                InterlockedExchange(PatternHits[pattern], 1u, previous);
            }
        }
    }
}
