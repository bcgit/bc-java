package org.bouncycastle.tls.crypto.jcajce;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCertificate;
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

    public void configureStatic(InputStream input) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
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

    public void usePeerCertificate(TlsCertificate certificate) throws IOException
    {
        // TODO[tls-ops] Check the domains match (although the agreement implementation enforces it anyway)
        // TODO[tls-ops] Is there a use-case where the TlsECDomain is determined from the certificate?
        this.peerPublicKey = JcaTlsCertificate.convert(certificate, domain.getCrypto().getHelper()).getPubKeyEC();
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
