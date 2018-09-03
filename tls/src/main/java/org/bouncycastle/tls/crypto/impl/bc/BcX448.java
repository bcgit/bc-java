package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.math.ec.rfc7748.X448;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.TlsImplUtils;
import org.bouncycastle.util.Arrays;

/**
 * Support class for X448 using the BC light-weight library.
 */
public class BcX448 implements TlsAgreement
{
    protected final BcTlsCrypto crypto;
    protected final byte[] privateKey = new byte[56];
    protected final byte[] peerPublicKey = new byte[56];

    public BcX448(BcTlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    public byte[] generateEphemeral() throws IOException
    {
        crypto.getSecureRandom().nextBytes(privateKey);

        byte[] publicKey = new byte[56];
        X448.scalarMultBase(privateKey, 0, publicKey, 0);
        return publicKey;
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        if (peerValue == null || peerValue.length != 56)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        System.arraycopy(peerValue, 0, peerPublicKey, 0, 56);
    }

    public TlsSecret calculateSecret() throws IOException
    {
        byte[] secret = new byte[56];
        X448.scalarMult(privateKey, 0, peerPublicKey, 0, secret, 0);

        Arrays.fill(privateKey, (byte)0);
        Arrays.fill(peerPublicKey, (byte)0);

        if (TlsImplUtils.isAllZeroes(secret))
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        return crypto.adoptLocalSecret(secret);
    }
}
