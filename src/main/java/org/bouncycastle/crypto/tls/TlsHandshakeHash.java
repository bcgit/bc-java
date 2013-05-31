package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.Digest;

interface TlsHandshakeHash
    extends Digest
{

    void init(TlsContext context);

    TlsHandshakeHash commit();

    TlsHandshakeHash fork();
}
