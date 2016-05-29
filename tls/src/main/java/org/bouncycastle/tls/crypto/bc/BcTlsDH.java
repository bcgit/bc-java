package org.bouncycastle.tls.crypto.bc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
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

    public void generateEphemeral(OutputStream output) throws IOException
    {
        this.localKeyPair = domain.generateDHKeyPair();
        domain.writeDHPublicKey((DHPublicKeyParameters)localKeyPair.getPublic(), output);
    }

    public void receivePeerValue(InputStream input) throws IOException
    {
        this.peerPublicKey = domain.readDHPublicKey(input);
    }

    public TlsSecret calculateSecret() throws IOException
    {
        byte[] data = domain.calculateDHAgreement(peerPublicKey, (DHPrivateKeyParameters)localKeyPair.getPrivate());
        return new BcTlsSecret(data);
    }
}
