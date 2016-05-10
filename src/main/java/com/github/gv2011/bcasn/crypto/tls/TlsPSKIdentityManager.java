package com.github.gv2011.bcasn.crypto.tls;

public interface TlsPSKIdentityManager
{
    byte[] getHint();

    byte[] getPSK(byte[] identity);
}
