package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

public class BcTlsX25519MLKem implements TlsAgreement
{
    protected final BcTlsX25519MLKemDomain domain;

    protected byte[] x25519PrivateKey;
    protected byte[] x25519PeerPublicKey;
    protected MLKEMPrivateKeyParameters mlkemPrivateKey;
    protected MLKEMPublicKeyParameters mlkemPublicKey;
    protected byte[] mlkemSecret;

    public BcTlsX25519MLKem(BcTlsX25519MLKemDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.x25519PrivateKey = domain.generateX25519PrivateKey();
        byte[] x25519PublicKey = domain.getX25519PublicKey(x25519PrivateKey);

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
        this.x25519PeerPublicKey = Arrays.copyOfRange(peerValue, peerValue.length - X25519.POINT_SIZE, peerValue.length);
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
        byte[] x25519Secret = domain.calculateX25519Secret(x25519PrivateKey, x25519PeerPublicKey);
        TlsSecret secret = domain.adoptLocalSecret(Arrays.concatenate(mlkemSecret, x25519Secret));
        this.x25519PrivateKey = null;
        this.mlkemSecret = null;
        return secret;
    }
}
