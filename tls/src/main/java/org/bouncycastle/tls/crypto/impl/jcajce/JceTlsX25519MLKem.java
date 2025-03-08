package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

public class JceTlsX25519MLKem implements TlsAgreement
{
    protected final JceTlsX25519MLKemDomain domain;

    protected KeyPair x25519LocalKeyPair;
    protected PublicKey x25519PeerPublicKey;
    protected MLKEMPrivateKeyParameters mlkemPrivateKey;
    protected MLKEMPublicKeyParameters mlkemPublicKey;
    protected byte[] mlkemSecret;

    public JceTlsX25519MLKem(JceTlsX25519MLKemDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.x25519LocalKeyPair = domain.generateX25519KeyPair();
        byte[] x25519PublicKey = domain.encodeX25519PublicKey(x25519LocalKeyPair.getPublic());

        if (domain.isServer())
        {
            SecretWithEncapsulation encap = domain.getMLKemDomain().encapsulate(mlkemPublicKey);
            this.mlkemPublicKey = null;
            this.mlkemSecret = encap.getSecret();
            byte[] mlkemValue = encap.getEncapsulation();
            return Arrays.concatenate(mlkemValue, x25519PublicKey);
        }
        else
        {
            AsymmetricCipherKeyPair kp = domain.getMLKemDomain().generateKeyPair();
            this.mlkemPrivateKey = (MLKEMPrivateKeyParameters)kp.getPrivate();
            byte[] mlkemValue = domain.getMLKemDomain().encodePublicKey((MLKEMPublicKeyParameters)kp.getPublic());
            return Arrays.concatenate(mlkemValue, x25519PublicKey);
        }
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        this.x25519PeerPublicKey = domain.decodeX25519PublicKey(Arrays.copyOfRange(peerValue, peerValue.length - X25519.POINT_SIZE, peerValue.length));
        byte[] mlkemValue = Arrays.copyOf(peerValue, peerValue.length - X25519.POINT_SIZE);

        if (domain.isServer())
        {
            this.mlkemPublicKey = domain.getMLKemDomain().decodePublicKey(mlkemValue);
        }
        else
        {
            this.mlkemSecret = domain.getMLKemDomain().decapsulate(mlkemPrivateKey, mlkemValue);
            this.mlkemPrivateKey = null;
        }
    }

    public TlsSecret calculateSecret() throws IOException
    {
        byte[] x25519Secret = domain.calculateX25519Agreement(x25519LocalKeyPair.getPrivate(), x25519PeerPublicKey);
        TlsSecret secret = domain.adoptLocalSecret(Arrays.concatenate(mlkemSecret, x25519Secret));
        this.mlkemSecret = null;
        return secret;
    }
}
