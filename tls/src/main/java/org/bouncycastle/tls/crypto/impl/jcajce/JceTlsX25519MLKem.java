package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
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
    protected AsymmetricCipherKeyPair mlkemLocalKeyPair;
    protected MLKEMPublicKeyParameters mlkemPeerPublicKey;

    protected byte[] mlkemCiphertext;
    protected byte[] mlkemSecret;

    public JceTlsX25519MLKem(JceTlsX25519MLKemDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.x25519LocalKeyPair = domain.generateX25519KeyPair();
        byte[] x25519Key = domain.encodeX25519PublicKey(x25519LocalKeyPair.getPublic());
        byte[] mlkemKey;
        if (domain.getKemDomain().getTlsKemConfig().isServer())
        {
            mlkemKey = Arrays.clone(mlkemCiphertext);
        }
        else
        {
            this.mlkemLocalKeyPair = domain.getKemDomain().generateKeyPair();
            mlkemKey = domain.getKemDomain().encodePublicKey((MLKEMPublicKeyParameters)mlkemLocalKeyPair.getPublic());

        }
        return Arrays.concatenate(mlkemKey, x25519Key);
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        byte[] xdhKey = Arrays.copyOfRange(peerValue, peerValue.length - domain.getX25519PublicKeyByteLength(), peerValue.length);
        byte[] mlkemKey = Arrays.copyOf(peerValue,peerValue.length - domain.getX25519PublicKeyByteLength());
        this.x25519PeerPublicKey = domain.decodeX25519PublicKey(xdhKey);
        if (domain.getKemDomain().getTlsKemConfig().isServer())
        {
            this.mlkemPeerPublicKey = domain.getKemDomain().decodePublicKey(mlkemKey);
            SecretWithEncapsulation encap = domain.getKemDomain().encapsulate(mlkemPeerPublicKey);
            this.mlkemCiphertext = encap.getEncapsulation();
            mlkemSecret = encap.getSecret();
        }
        else
        {
            this.mlkemCiphertext = Arrays.clone(mlkemKey);
        }
    }

    public TlsSecret calculateSecret() throws IOException
    {
        byte[] x25519Secret = domain.calculateX25519AgreementToBytes(x25519LocalKeyPair.getPrivate(), x25519PeerPublicKey);
        if (!domain.getKemDomain().getTlsKemConfig().isServer())
        {
            mlkemSecret = domain.getKemDomain().decapsulate((MLKEMPrivateKeyParameters)mlkemLocalKeyPair.getPrivate(), mlkemCiphertext).extract();
        }
        return domain.getKemDomain().adoptLocalSecret(Arrays.concatenate(mlkemSecret, x25519Secret));
    }
}
