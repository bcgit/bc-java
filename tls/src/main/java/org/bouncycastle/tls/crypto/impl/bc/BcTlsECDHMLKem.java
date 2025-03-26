package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

public class BcTlsECDHMLKem implements TlsAgreement
{
    protected final BcTlsECDHMLKemDomain domain;

    protected AsymmetricCipherKeyPair ecLocalKeyPair;
    protected ECPublicKeyParameters ecPeerPublicKey;
    protected MLKEMPrivateKeyParameters mlkemPrivateKey;
    protected MLKEMPublicKeyParameters mlkemPublicKey;
    protected byte[] mlkemSecret;

    public BcTlsECDHMLKem(BcTlsECDHMLKemDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.ecLocalKeyPair = domain.getECDomain().generateKeyPair();
        byte[] ecPublickey = domain.getECDomain().encodePublicKey((ECPublicKeyParameters)ecLocalKeyPair.getPublic());

        if (domain.isServer())
        {
            SecretWithEncapsulation encap = domain.getMLKemDomain().encapsulate(mlkemPublicKey);
            this.mlkemPublicKey = null;
            this.mlkemSecret = encap.getSecret();
            byte[] mlkemValue = encap.getEncapsulation();
            return Arrays.concatenate(ecPublickey, mlkemValue);
        }
        else
        {
            AsymmetricCipherKeyPair kp = domain.getMLKemDomain().generateKeyPair();
            this.mlkemPrivateKey = (MLKEMPrivateKeyParameters)kp.getPrivate();
            byte[] mlkemValue = domain.getMLKemDomain().encodePublicKey((MLKEMPublicKeyParameters)kp.getPublic());
            return Arrays.concatenate(ecPublickey, mlkemValue);
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
        byte[] ecSecret = domain.getECDomain().calculateECDHAgreementBytes((ECPrivateKeyParameters)ecLocalKeyPair.getPrivate(), ecPeerPublicKey);
        TlsSecret secret = domain.adoptLocalSecret(Arrays.concatenate(ecSecret, mlkemSecret));
        this.mlkemSecret = null;
        return secret;
    }
}
