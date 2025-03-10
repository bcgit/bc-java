package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

public class BcTlsX25519MLKem implements TlsAgreement
{
    protected final BcTlsX25519MLKemDomain domain;

    protected AsymmetricCipherKeyPair mlkemLocalKeyPair;
    protected MLKEMPublicKeyParameters mlkemPeerPublicKey;
    protected byte[] x25519PrivateKey;
    protected byte[] x25519PeerPublicKey;

    protected byte[] mlkemCiphertext;
    protected byte[] mlkemSecret;

    public BcTlsX25519MLKem(BcTlsX25519MLKemDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.x25519PrivateKey = domain.generateX25519PrivateKey();
        byte[] x25519Key = domain.getX25519PublicKey(x25519PrivateKey);
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
        this.x25519PeerPublicKey = Arrays.copyOfRange(peerValue, peerValue.length - domain.getX25519PublicKeyByteLength(), peerValue.length);
        byte[] mlkemKey = Arrays.copyOf(peerValue, peerValue.length - domain.getX25519PublicKeyByteLength());
        if (domain.getKemDomain().getTlsKemConfig().isServer())
        {
            this.mlkemPeerPublicKey = domain.getKemDomain().decodePublicKey(mlkemKey);
            SecretWithEncapsulation encap = domain.getKemDomain().encapsulate(mlkemPeerPublicKey);
            mlkemCiphertext = encap.getEncapsulation();
            mlkemSecret = encap.getSecret();
        }
        else
        {
            this.mlkemCiphertext = Arrays.clone(mlkemKey);
        }
    }

    public TlsSecret calculateSecret() throws IOException
    {
        byte[] x25519Secret = domain.calculateX25519Secret(x25519PrivateKey, x25519PeerPublicKey);
        if (!domain.getKemDomain().getTlsKemConfig().isServer())
        {
            mlkemSecret = domain.getKemDomain().decapsulate((MLKEMPrivateKeyParameters)mlkemLocalKeyPair.getPrivate(), mlkemCiphertext).extract();
        }
        return domain.getKemDomain().adoptLocalSecret(Arrays.concatenate(mlkemSecret, x25519Secret));
    }
}
