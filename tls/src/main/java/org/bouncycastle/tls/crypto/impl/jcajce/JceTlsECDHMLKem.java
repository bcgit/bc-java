package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

public class JceTlsECDHMLKem implements TlsAgreement
{
    protected final JceTlsECDHMLKemDomain domain;

    protected KeyPair ecLocalKeyPair;
    protected PublicKey ecPeerPublicKey;
    protected MLKEMPrivateKeyParameters mlkemPrivateKey;
    protected MLKEMPublicKeyParameters mlkemPublicKey;
    protected byte[] mlkemSecret;

    public JceTlsECDHMLKem(JceTlsECDHMLKemDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.ecLocalKeyPair = domain.getECDomain().generateKeyPair();
        byte[] ecPublicKey = domain.getECDomain().encodePublicKey(ecLocalKeyPair.getPublic());

        if (domain.isServer())
        {
            SecretWithEncapsulation encap = domain.getMLKemDomain().encapsulate(mlkemPublicKey);
            this.mlkemPublicKey = null;
            this.mlkemSecret = encap.getSecret();
            byte[] mlkemValue = encap.getEncapsulation();
            return Arrays.concatenate(ecPublicKey, mlkemValue);
        }
        else
        {
            AsymmetricCipherKeyPair kp = domain.getMLKemDomain().generateKeyPair();
            this.mlkemPrivateKey = (MLKEMPrivateKeyParameters)kp.getPrivate();
            byte[] mlkemValue = domain.getMLKemDomain().encodePublicKey((MLKEMPublicKeyParameters)kp.getPublic());
            return Arrays.concatenate(ecPublicKey, mlkemValue);
        }
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        this.ecPeerPublicKey = domain.getECDomain().decodePublicKey(Arrays.copyOf(peerValue, domain.getECDomain().getPublicKeyByteLength()));
        byte[] mlkemValue = Arrays.copyOfRange(peerValue, domain.getECDomain().getPublicKeyByteLength(), peerValue.length);

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
        byte[] ecSecret = domain.getECDomain().calculateECDHAgreementBytes(ecLocalKeyPair.getPrivate(), ecPeerPublicKey);
        TlsSecret secret = domain.adoptLocalSecret(Arrays.concatenate(ecSecret, mlkemSecret));
        this.mlkemSecret = null;
        return secret;
    }
}
