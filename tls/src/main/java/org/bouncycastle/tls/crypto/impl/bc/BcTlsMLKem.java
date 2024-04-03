package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;

public class BcTlsMLKem implements TlsAgreement
{
    protected final BcTlsMLKemDomain domain;

    protected KyberPrivateKeyParameters privateKey;
    protected KyberPublicKeyParameters publicKey;
    protected TlsSecret secret;

    public BcTlsMLKem(BcTlsMLKemDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        if (domain.isServer())
        {
            SecretWithEncapsulation encap = domain.encapsulate(publicKey);
            this.publicKey = null;
            this.secret = domain.adoptLocalSecret(encap.getSecret());
            return encap.getEncapsulation();
        }
        else
        {
            AsymmetricCipherKeyPair kp = domain.generateKeyPair();
            this.privateKey = (KyberPrivateKeyParameters)kp.getPrivate();
            return domain.encodePublicKey((KyberPublicKeyParameters)kp.getPublic());
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
