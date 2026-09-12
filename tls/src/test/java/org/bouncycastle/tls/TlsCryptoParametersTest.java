package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsDTLS13Cipher;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import junit.framework.TestCase;

/**
 * {@link TlsCryptoParameters#getSecurityParameters()} resolves the handshake parameters while a handshake is
 * in progress and the connection parameters afterwards, so that a cipher can still be built once
 * {@code handshakeComplete} has nulled the handshake parameters. RFC 9147 4.6.3 key update needs exactly that.
 */
public class TlsCryptoParametersTest
    extends TestCase
{
    private static TlsPeer createPeer(TlsCrypto crypto)
    {
        return new DefaultTlsClient(crypto)
        {
            public TlsAuthentication getAuthentication()
            {
                return null;
            }
        };
    }

    private static AbstractTlsContext createContext(TlsCrypto crypto) throws Exception
    {
        return TlsAEADCipherDTLS13Test.createContext(crypto, false, CipherSuite.TLS_AES_128_GCM_SHA256,
            CryptoHashAlgorithm.sha256, new byte[32], new byte[32]);
    }

    /**
     * The neutrality claim in one assertion: while a handshake is in progress the new accessor returns the
     * very object the old one returns, so no existing (D)TLS caller can observe a difference.
     */
    public void testDuringHandshakeReturnsTheHandshakeParameters() throws Exception
    {
        TlsCrypto crypto = new BcTlsCrypto();
        AbstractTlsContext context = createContext(crypto);

        SecurityParameters handshake = context.getSecurityParametersHandshake();
        assertNotNull(handshake);
        assertNull(context.getSecurityParametersConnection());

        TlsCryptoParameters cryptoParams = new TlsCryptoParameters(context);
        assertSame(handshake, cryptoParams.getSecurityParameters());
        assertSame(handshake, cryptoParams.getSecurityParametersHandshake());
    }

    public void testAfterHandshakeReturnsTheConnectionParameters() throws Exception
    {
        TlsCrypto crypto = new BcTlsCrypto();
        TlsPeer peer = createPeer(crypto);
        AbstractTlsContext context = createContext(crypto);

        SecurityParameters handshake = context.getSecurityParametersHandshake();
        context.handshakeComplete(peer, null);

        assertNull(context.getSecurityParametersHandshake());
        assertSame(handshake, context.getSecurityParametersConnection());

        TlsCryptoParameters cryptoParams = new TlsCryptoParameters(context);
        assertSame(handshake, cryptoParams.getSecurityParameters());
    }

    /**
     * The blocker itself: a DTLS 1.3 AEAD cipher must be constructible after the handshake has completed,
     * because that is when a key update happens.
     */
    public void testCipherIsConstructedAfterHandshakeCompletes() throws Exception
    {
        TlsCrypto crypto = new BcTlsCrypto();
        TlsPeer peer = createPeer(crypto);
        AbstractTlsContext context = createContext(crypto);

        context.handshakeComplete(peer, null);

        TlsDTLS13Cipher cipher = (TlsDTLS13Cipher)TlsUtils.initCipher(context);
        assertNotNull(cipher);
    }
}
