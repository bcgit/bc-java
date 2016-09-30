package org.bouncycastle.tls.crypto.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;

public class JceTlsECDH
    implements TlsAgreement
{
    protected JcaTlsECDomain domain;
    protected KeyPair localKeyPair;
    protected ECPublicKey peerPublicKey;

    public JceTlsECDH(JcaTlsECDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.localKeyPair = domain.generateKeyPair();
        return domain.encodePublicKey((ECPublicKey)localKeyPair.getPublic());
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        this.peerPublicKey = domain.decodePublicKey(peerValue);
    }

    public TlsSecret calculateSecret() throws IOException
    {
        try
        {
            byte[] data = domain.calculateECDHAgreement(peerPublicKey, (ECPrivateKey)localKeyPair.getPrivate());
            return domain.getCrypto().adoptSecret(data);
        }
        catch (GeneralSecurityException e)
        {
            throw new IOException("cannot calculate secret", e);
        }
    }
}
