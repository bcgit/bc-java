package org.bouncycastle.crypto.random;

import org.bouncycastle.crypto.prng.SP80090DRBG;
import org.bouncycastle.crypto.prng.EntropySource;

interface DRBGProvider
{
    SP80090DRBG get(EntropySource entropySource, int entropyBitsRequired);
}
