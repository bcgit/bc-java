package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * Support class for ephemeral Diffie-Hellman using the JCE.
 */
public class JceTlsDH
    implements TlsAgreement
{
    protected JceTlsDHDomain domain;
    protected KeyPair localKeyPair;
    protected DHPublicKey peerPublicKey;

    public JceTlsDH(JceTlsDHDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.localKeyPair = domain.generateKeyPair();
        return domain.encodePublicKey((DHPublicKey)localKeyPair.getPublic());
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        this.peerPublicKey = domain.decodePublicKey(peerValue);
    }

    public TlsSecret calculateSecret() throws IOException
    {
        try
        {
            byte[] data = domain.calculateDHAgreement(peerPublicKey, (DHPrivateKey)localKeyPair.getPrivate());
            return domain.getCrypto().adoptLocalSecret(data);
        }
        catch (GeneralSecurityException e)
        {
            throw new IOException("cannot calculate secret", e);
        }
    }
}
