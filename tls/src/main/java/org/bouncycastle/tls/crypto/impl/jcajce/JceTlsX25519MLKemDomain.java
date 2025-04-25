package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsKemConfig;
import org.bouncycastle.tls.crypto.TlsKemDomain;
import org.bouncycastle.util.Arrays;

public class JceTlsX25519MLKemDomain implements TlsKemDomain
{
    protected final JcaTlsCrypto crypto;
    protected final boolean isServer;
    private final JceX25519Domain x25519Domain;
    private final JceTlsMLKemDomain mlkemDomain;

    public JceTlsX25519MLKemDomain(JcaTlsCrypto crypto, TlsKemConfig kemConfig)
    {
        this.crypto = crypto;
        this.x25519Domain = new JceX25519Domain(crypto);
        this.mlkemDomain = new JceTlsMLKemDomain(crypto, kemConfig);
        this.isServer = kemConfig.isServer();
    }

    public JceTlsSecret adoptLocalSecret(byte[] secret)
    {
        return crypto.adoptLocalSecret(secret);
    }

    public TlsAgreement createKem()
    {
        return new JceTlsX25519MLKem(this);
    }

    public boolean isServer()
    {
        return isServer;
    }

    public JceTlsMLKemDomain getMLKemDomain()
    {
        return mlkemDomain;
    }


    public KeyPair generateX25519KeyPair()
    {
        try
        {
            return x25519Domain.generateKeyPair();
        }
        catch (Exception e)
        {
            throw Exceptions.illegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }

    public byte[] encodeX25519PublicKey(PublicKey publicKey) throws IOException
    {
        return XDHUtil.encodePublicKey(publicKey);
    }

    public PublicKey decodeX25519PublicKey(byte[] x25519Key) throws IOException
    {
        return x25519Domain.decodePublicKey(x25519Key);
    }

    public byte[] calculateX25519Agreement(PrivateKey privateKey, PublicKey publicKey) throws IOException
    {
        try
        {
            byte[] secret =  crypto.calculateKeyAgreement("X25519", privateKey, publicKey, "TlsPremasterSecret");
            if (secret == null || secret.length != 32)
            {
                throw new TlsCryptoException("invalid secret calculated");
            }
            if (Arrays.areAllZeroes(secret, 0, secret.length))
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
            return secret;
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("cannot calculate secret", e);
        }
    }
}
