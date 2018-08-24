package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

/**
 * Support class for X25519 using the BC light-weight library.
 */
public class BcX25519 implements TlsAgreement
{
    protected final BcTlsCrypto crypto;
    protected final byte[] privateKey = new byte[32];
    protected final byte[] peerPublicKey = new byte[32];

    public BcX25519(BcTlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    public byte[] generateEphemeral() throws IOException
    {
        crypto.getSecureRandom().nextBytes(privateKey);

        byte[] publicKey = new byte[32];
        X25519.scalarMultBase(privateKey, 0, publicKey, 0);
        return publicKey;
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        if (peerValue == null || peerValue.length != 32)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        System.arraycopy(peerValue, 0, peerPublicKey, 0, 32);
    }

    public TlsSecret calculateSecret() throws IOException
    {
        byte[] secret = new byte[32];
        X25519.scalarMult(privateKey, 0, peerPublicKey, 0, secret, 0);

        Arrays.fill(privateKey, (byte)0);
        Arrays.fill(peerPublicKey, (byte)0);

        int bits = 0;
        for (int i = 0; i < 32; ++i)
        {
            bits |= secret[i];
        }
        if (bits == 0)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        return crypto.adoptLocalSecret(secret);
    }
}
