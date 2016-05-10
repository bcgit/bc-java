package com.github.gv2011.bcasn.crypto.modes.gcm;

public interface GCMExponentiator
{
    void init(byte[] x);
    void exponentiateX(long pow, byte[] output);
}
