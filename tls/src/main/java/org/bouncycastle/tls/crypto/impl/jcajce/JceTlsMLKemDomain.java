package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsKemConfig;
import org.bouncycastle.tls.crypto.TlsKemDomain;

public class JceTlsMLKemDomain implements TlsKemDomain
{
    protected final JcaTlsCrypto crypto;
    protected final String kemName;
    protected final boolean isServer;

    public JceTlsMLKemDomain(JcaTlsCrypto crypto, TlsKemConfig kemConfig)
    {
        this.crypto = crypto;
        this.kemName = NamedGroup.getKemName(kemConfig.getNamedGroup());
        this.isServer = kemConfig.isServer();
    }

    public JceTlsSecret adoptLocalSecret(byte[] secret)
    {
        return crypto.adoptLocalSecret(secret);
    }

    public TlsAgreement createKem()
    {
        return new JceTlsMLKem(this);
    }

    public JceTlsSecret decapsulate(PrivateKey privateKey, byte[] ciphertext)
    {
        return KemUtil.decapsulate(crypto, kemName, privateKey, ciphertext);
    }

    public PublicKey decodePublicKey(byte[] encoding)
        throws IOException
    {
        return KemUtil.decodePublicKey(crypto, kemName, encoding);
    }

    public SecretKeyWithEncapsulation encapsulate(PublicKey publicKey)
    {
        return KemUtil.encapsulate(crypto, kemName, publicKey);
    }

    public byte[] encodePublicKey(PublicKey publicKey)
        throws IOException
    {
        return KemUtil.encodePublicKey(publicKey);
    }

    public KeyPair generateKeyPair()
    {
        return KemUtil.generateKeyPair(crypto, kemName);
    }

    public boolean isServer()
    {
        return isServer;
    }
}
