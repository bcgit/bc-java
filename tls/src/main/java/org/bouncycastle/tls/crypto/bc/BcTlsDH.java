package org.bouncycastle.tls.crypto.bc;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsSecret;

public class BcTlsDH implements TlsAgreement
{
    protected BcTlsDHDomain domain;
    protected AsymmetricCipherKeyPair localKeyPair;
    protected DHPublicKeyParameters peerPublicKey;

    public BcTlsDH(BcTlsDHDomain domain)
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
        this.peerPublicKey = TlsDHUtils.validateDHPublicKey(domain.decodePublicKey(peerValue));
    }

    public void usePeerCertificate(TlsCertificate certificate) throws IOException
    {
        // TODO[tls-ops] Check the domains match (although the agreement implementation enforces it anyway)
        // TODO[tls-ops] Is there a use-case where the TlsDHDomain is determined from the certificate?
        this.peerPublicKey = BcTlsCertificate.convert(domain.getCrypto(), certificate).getPubKeyDH();
    }

    public TlsSecret calculateSecret() throws IOException
    {
        byte[] data = domain.calculateDHAgreement(peerPublicKey, (DHPrivateKeyParameters)localKeyPair.getPrivate());
        return domain.getCrypto().adoptSecret(data);
    }
}
