#include <stdint.h>
#include <stdio.h>
#include <climits>
#include "string_utils.h"

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string value = provider.ConsumeRandomLengthString();
    std::string ending = provider.ConsumeRandomLengthString();

    ends_with(value, ending);

    return 0;
}