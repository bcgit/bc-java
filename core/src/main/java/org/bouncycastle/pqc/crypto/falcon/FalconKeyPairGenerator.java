package org.bouncycastle.pqc.crypto.falcon;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class FalconKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{

    private FalconKeyGenerationParameters params;
    private SecureRandom random;
    private FalconNIST nist;
    private int logn;
    private int noncelen;

    private int pk_size;
    private int sk_size;

    public void init(KeyGenerationParameters param)
    {
        this.params = (FalconKeyGenerationParameters)param;
        this.random = param.getRandom();
        this.logn = ((FalconKeyGenerationParameters)param).getParameters().getLogN();
        this.noncelen = ((FalconKeyGenerationParameters)param).getParameters().getNonceLength();
        this.nist = new FalconNIST(logn, noncelen, random);
        int n = 1 << this.logn;
        int sk_coeff_size = 8;
        if (n == 1024)
        {
            sk_coeff_size = 5;
        }
        else if (n == 256 || n == 512)
        {
            sk_coeff_size = 6;
        }
        else if (n == 64 || n == 128)
        {
            sk_coeff_size = 7;
        }
        this.pk_size = 1 + (14 * n / 8);
        this.sk_size = 1 + (2 * sk_coeff_size * n / 8) + (n);
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        byte[] pk, sk;
        pk = new byte[pk_size];
        sk = new byte[sk_size];
        byte[][] keyData = nist.crypto_sign_keypair(pk, 0, sk, 0);
        FalconParameters p = ((FalconKeyGenerationParameters)this.params).getParameters();
        FalconPrivateKeyParameters privk = new FalconPrivateKeyParameters(p, keyData[1], keyData[2], keyData[3], keyData[0]);
        FalconPublicKeyParameters pubk = new FalconPublicKeyParameters(p, keyData[0]);
        return new AsymmetricCipherKeyPair(pubk, privk);
    }
}
