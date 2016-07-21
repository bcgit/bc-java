package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.ConnectionEnd;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;

public interface TlsCertificate
{
    /**
     * @param signatureAlgorithm
     *            {@link SignatureAlgorithm}
     */
    TlsVerifier createVerifier(short signatureAlgorithm) throws IOException;

    byte[] getEncoded() throws IOException;

    /**
     * @param connectionEnd
     *            {@link ConnectionEnd}
     * @param keyExchange
     *            {@link KeyExchangeAlgorithm}
     */
    TlsCertificate useInRole(int connectionEnd, int keyExchangeAlgorithm) throws IOException;
}
