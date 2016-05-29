package org.bouncycastle.tls.crypto.bc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;

public class BcTlsECDH implements TlsAgreement
{
    protected BcTlsECDomain domain;
    protected AsymmetricCipherKeyPair localKeyPair;
    protected ECPublicKeyParameters peerPublicKey;

    public BcTlsECDH(BcTlsECDomain domain)
    {
        this.domain = domain;
    }

    public void configureStatic(InputStream input) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void generateEphemeral(OutputStream output) throws IOException
    {
        this.localKeyPair = domain.generateECKeyPair();
        domain.writeECPublicKey((ECPublicKeyParameters)localKeyPair.getPublic(), output);
    }

    public void receivePeerValue(InputStream input) throws IOException
    {
        this.peerPublicKey = domain.readECPublicKey(input);
    }

    public TlsSecret calculateSecret() throws IOException
    {
        byte[] data = domain.calculateAgreement(peerPublicKey, (ECPrivateKeyParameters)localKeyPair.getPrivate());
        return new BcTlsSecret(data);
    }
}
