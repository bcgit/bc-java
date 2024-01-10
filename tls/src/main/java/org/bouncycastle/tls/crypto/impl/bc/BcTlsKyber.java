package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsPQCKemMode;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

public class BcTlsKyber implements TlsAgreement
{
    protected final BcTlsKyberDomain domain;

    protected AsymmetricCipherKeyPair localKeyPair;
    protected KyberPublicKeyParameters peerPublicKey;
    protected byte[] ciphertext;
    protected byte[] secret;

    public BcTlsKyber(BcTlsKyberDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        if (TlsPQCKemMode.PQC_KEM_CLIENT.equals(domain.getTlsPQCConfig().getTlsPQCKemMode()))
        {
            this.localKeyPair = domain.generateKeyPair();
            return domain.encodePublicKey((KyberPublicKeyParameters)localKeyPair.getPublic());
        }
        else
        {
            return Arrays.clone(ciphertext);
        }
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        if (TlsPQCKemMode.PQC_KEM_CLIENT.equals(domain.getTlsPQCConfig().getTlsPQCKemMode()))
        {
            this.ciphertext = Arrays.clone(peerValue);
        }
        else
        {
            this.peerPublicKey = domain.decodePublicKey(peerValue);
            SecretWithEncapsulation encap = domain.enCap(peerPublicKey);
            ciphertext = encap.getEncapsulation();
            secret = encap.getSecret();
        }
    }

    public TlsSecret calculateSecret() throws IOException
    {
        if (TlsPQCKemMode.PQC_KEM_CLIENT.equals(domain.getTlsPQCConfig().getTlsPQCKemMode()))
        {
            return domain.adoptLocalSecret(domain.deCap((KyberPrivateKeyParameters)localKeyPair.getPrivate(), ciphertext));
        }
        else
        {
            return domain.adoptLocalSecret(secret);
        }
    }
}
