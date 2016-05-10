package com.github.gv2011.bcasn.crypto.prng;

import com.github.gv2011.bcasn.crypto.prng.drbg.SP80090DRBG;

interface DRBGProvider
{
    SP80090DRBG get(EntropySource entropySource);
}
