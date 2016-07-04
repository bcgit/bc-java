package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.ConnectionEnd;
import org.bouncycastle.tls.KeyExchangeAlgorithm;

public interface TlsCertificate
{
    byte[] getEncoded() throws IOException;

    /**
     * 
     * @param connectionEnd {@link ConnectionEnd}
     * @param keyExchange {@link KeyExchangeAlgorithm}
     * @return
     */
    TlsCertificate useInRole(int connectionEnd, int keyExchangeAlgorithm) throws IOException;
}
