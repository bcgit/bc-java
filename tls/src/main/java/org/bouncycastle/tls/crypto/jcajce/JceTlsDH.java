package org.bouncycastle.tls.crypto.jcajce;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsSecret;

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

    public void configureStatic(InputStream input) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.localKeyPair = domain.generateKeyPair();
        return domain.encodePublicKey((DHPublicKeyParameters)localKeyPair.getPublic());
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        this.peerPublicKey = domain.decodePublicKey(peerValue);
    }

    public void usePeerCertificate(TlsCertificate certificate) throws IOException
    {
        // TODO[tls-ops] Check the domains match (although the agreement implementation enforces it anyway)
        // TODO[tls-ops] Is there a use-case where the TlsDHDomain is determined from the certificate?
        this.peerPublicKey = JcaTlsCertificate.convert(certificate, domain.getCrypto().getHelper()).getPubKeyDH();
    }

    public TlsSecret calculateSecret() throws IOException
    {
        try
        {
            byte[] data = domain.calculateDHAgreement(peerPublicKey, (DHPrivateKey)localKeyPair.getPrivate());
            return domain.getCrypto().adoptSecret(data);
        }
        catch (GeneralSecurityException e)
        {
            throw new IOException("cannot calculate secret", e);
        }
    }
}
