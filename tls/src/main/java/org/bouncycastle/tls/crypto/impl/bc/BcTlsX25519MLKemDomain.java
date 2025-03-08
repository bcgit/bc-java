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
    protected final BcTlsCrypto crypto;
    protected final boolean isServer;
    protected final BcTlsMLKemDomain mlkemDomain;

    public BcTlsX25519MLKemDomain(BcTlsCrypto crypto, TlsKemConfig kemConfig)
    {
        this.crypto = crypto;
        this.mlkemDomain = new BcTlsMLKemDomain(crypto, kemConfig);
        this.isServer = kemConfig.isServer();
    }

    public BcTlsSecret adoptLocalSecret(byte[] secret)
    {
        return crypto.adoptLocalSecret(secret);
    }

    public TlsAgreement createKem()
    {
        return new BcTlsX25519MLKem(this);
    }

    public boolean isServer()
    {
        return isServer;
    }

    public BcTlsMLKemDomain getMLKemDomain()
    {
        return mlkemDomain;
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
