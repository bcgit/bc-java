package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * Support class for ephemeral Diffie-Hellman using the BC light-weight library.
 */
public class BcTlsDH implements TlsAgreement
{
    protected BcTlsDHDomain domain;
    protected AsymmetricCipherKeyPair localKeyPair;
    protected DHPublicKeyParameters peerPublicKey;

    public BcTlsDH(BcTlsDHDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.localKeyPair = domain.generateKeyPair();
        return domain.encodePublicKey((DHPublicKeyParameters)localKeyPair.getPublic());
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        DHPublicKeyParameters dhKey = domain.decodePublicKey(peerValue);

        TlsDHUtils.validateDHPublicValues(dhKey.getY(), dhKey.getParameters().getP());

        this.peerPublicKey = dhKey;
    }

    public TlsSecret calculateSecret() throws IOException
    {
        byte[] data = domain.calculateDHAgreement(peerPublicKey, (DHPrivateKeyParameters)localKeyPair.getPrivate());
        return domain.getCrypto().adoptLocalSecret(data);
    }
}
