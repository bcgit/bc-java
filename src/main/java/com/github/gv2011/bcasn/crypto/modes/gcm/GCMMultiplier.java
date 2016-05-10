package com.github.gv2011.bcasn.crypto.modes.gcm;

public interface GCMMultiplier
{
    void init(byte[] H);
    void multiplyH(byte[] x);
}
