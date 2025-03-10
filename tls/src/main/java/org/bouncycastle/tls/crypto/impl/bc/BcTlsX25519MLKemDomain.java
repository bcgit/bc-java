package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsKemConfig;
import org.bouncycastle.tls.crypto.TlsKemDomain;

public class BcTlsX25519MLKemDomain implements TlsKemDomain
{
    protected final BcTlsMLKemDomain kemDomain;
    protected final BcTlsCrypto crypto;

    public BcTlsX25519MLKemDomain(BcTlsCrypto crypto, TlsKemConfig kemConfig)
    {
        this.kemDomain = new BcTlsMLKemDomain(crypto, kemConfig);
        this.crypto = crypto;
    }

    public TlsAgreement createKem()
    {
        return new BcTlsX25519MLKem(this);
    }

    public BcTlsMLKemDomain getKemDomain()
    {
        return kemDomain;
    }

    public byte[] generateX25519PrivateKey() throws IOException
    {
        byte[] privateKey = new byte[X25519.SCALAR_SIZE];
        crypto.getSecureRandom().nextBytes(privateKey);
        return privateKey;
    }

    public byte[] getX25519PublicKey(byte[] privateKey) throws IOException
    {
        byte[] publicKey = new byte[X25519.POINT_SIZE];
        X25519.scalarMultBase(privateKey, 0, publicKey, 0);
        return publicKey;
    }

    public int getX25519PublicKeyByteLength() throws IOException
    {
        return X25519.POINT_SIZE;
    }

    public byte[] calculateX25519Secret(byte[] privateKey, byte[] peerPublicKey) throws IOException
    {
        byte[] secret = new byte[X25519.POINT_SIZE];
        if (!X25519.calculateAgreement(privateKey, 0, peerPublicKey, 0, secret, 0))
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
        return secret;
    }
}
