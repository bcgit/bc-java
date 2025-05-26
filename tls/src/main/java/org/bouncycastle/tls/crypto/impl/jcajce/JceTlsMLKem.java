package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;

public class JceTlsMLKem implements TlsAgreement
{
    protected final JceTlsMLKemDomain domain;

    protected PrivateKey privateKey;
    protected PublicKey publicKey;
    protected TlsSecret secret;

    public JceTlsMLKem(JceTlsMLKemDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        if (domain.isServer())
        {
            SecretKeyWithEncapsulation encap = domain.encapsulate(publicKey);
            this.publicKey = null;
            this.secret = domain.adoptLocalSecret(encap.getEncoded());
            return encap.getEncapsulation();
        }
        else
        {
            KeyPair kp = domain.generateKeyPair();
            this.privateKey = kp.getPrivate();
            return KemUtil.encodePublicKey(kp.getPublic());
        }
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        if (domain.isServer())
        {
            this.publicKey = domain.decodePublicKey(peerValue);
        }
        else
        {
            this.secret = domain.decapsulate(privateKey, peerValue);
            this.privateKey = null;
        }
    }

    public TlsSecret calculateSecret() throws IOException
    {
        TlsSecret secret = this.secret;
        this.secret = null;
        return secret;
    }
}
