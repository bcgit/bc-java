package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

public class JceTlsEcdhMlkem implements TlsAgreement
{
    protected final JceTlsEcdhMlkemDomain domain;

    protected KeyPair ecLocalKeyPair;
    protected PublicKey ecPeerPublicKey;
    protected AsymmetricCipherKeyPair kyberLocalKeyPair;
    protected KyberPublicKeyParameters kyberPeerPublicKey;
    protected byte[] kyberCiphertext;
    protected byte[] kyberSecret;
    protected TlsSecret secret;

    public JceTlsEcdhMlkem(JceTlsEcdhMlkemDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.ecLocalKeyPair = domain.getEcDomain().generateKeyPair();
        byte[] ecPublickey = domain.getEcDomain().encodePublicKey(ecLocalKeyPair.getPublic());
        if (domain.isServer())
        {
            return Arrays.concatenate(ecPublickey, kyberCiphertext);
        }
        else
        {
            this.kyberLocalKeyPair = domain.getMlkemDomain().generateKeyPair();
            byte[] kyberPublicKey = domain.getMlkemDomain().encodePublicKey((KyberPublicKeyParameters)kyberLocalKeyPair.getPublic());
            return Arrays.concatenate(ecPublickey, kyberPublicKey);
        }
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        this.ecPeerPublicKey = domain.getEcDomain().decodePublicKey(Arrays.copyOf(peerValue, domain.getEcDomain().getPublicKeyByteLength()));
        byte[] kyberValue = Arrays.copyOfRange(peerValue, domain.getEcDomain().getPublicKeyByteLength(), peerValue.length);
        if (domain.isServer())
        {
            this.kyberPeerPublicKey = domain.getMlkemDomain().decodePublicKey(kyberValue);
            SecretWithEncapsulation encap = domain.getMlkemDomain().encapsulate(kyberPeerPublicKey);
            kyberCiphertext = encap.getEncapsulation();
            kyberSecret = encap.getSecret();
        }
        else
        {
            this.kyberCiphertext = Arrays.clone(kyberValue);
        }
    }

    public TlsSecret calculateSecret() throws IOException
    {
        byte[] ecSecret = domain.getEcDomain().calculateECDHAgreementBytes(ecLocalKeyPair.getPrivate(), ecPeerPublicKey);
        if (domain.isServer())
        {
        }
        else
        {
            kyberSecret = domain.getMlkemDomain().decapsulate((KyberPrivateKeyParameters) kyberLocalKeyPair.getPrivate(), kyberCiphertext);
        }
        return domain.adoptLocalSecret(Arrays.concatenate(ecSecret, kyberSecret));
    }
}
