package com.github.gv2011.bcasn.crypto.prng;

public interface EntropySourceProvider
{
    EntropySource get(final int bitsRequired);
}
