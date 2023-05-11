package org.bouncycastle.jsse.provider;

import org.bouncycastle.tls.TlsContext;

interface ProvTlsPeer
{
    String getID();

    ProvSSLSession getSession();

    TlsContext getTlsContext();

    boolean isHandshakeComplete();
}
