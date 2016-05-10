package com.github.gv2011.bcasn.crypto.tls;

public interface TlsSession
{
    SessionParameters exportSessionParameters();

    byte[] getSessionID();

    void invalidate();

    boolean isResumable();
}
