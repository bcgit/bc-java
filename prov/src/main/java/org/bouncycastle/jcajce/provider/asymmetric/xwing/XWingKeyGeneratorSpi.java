package org.bouncycastle.jcajce.provider.asymmetric.xwing;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.crypto.xwing.XWingKEMExtractor;
import org.bouncycastle.pqc.crypto.xwing.XWingKEMGenerator;
import org.bouncycastle.util.Arrays;

public class XWingKeyGeneratorSpi
    extends KeyGeneratorSpi
{
    private KEMGenerateSpec genSpec;
    private SecureRandom random;
    private KEMExtractSpec extSpec;

    public XWingKeyGeneratorSpi()
    {
    }

    protected void engineInit(SecureRandom secureRandom)
    {
        throw new UnsupportedOperationException("Operation not supported");
    }

    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom)
        throws InvalidAlgorithmParameterException
    {
        this.random = secureRandom;
        if (algorithmParameterSpec instanceof KEMGenerateSpec)
        {
            this.genSpec = (KEMGenerateSpec)algorithmParameterSpec;
            this.extSpec = null;
            if (!(genSpec.getPublicKey() instanceof BCXWingPublicKey))
            {
                throw new InvalidAlgorithmParameterException("public key must be an X-WING key");
            }
        }
        else if (algorithmParameterSpec instanceof KEMExtractSpec)
        {
            this.genSpec = null;
            this.extSpec = (KEMExtractSpec)algorithmParameterSpec;
            if (!(extSpec.getPrivateKey() instanceof BCXWingPrivateKey))
            {
                throw new InvalidAlgorithmParameterException("private key must be an X-WING key");
            }
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unknown spec");
        }
    }

    protected void engineInit(int i, SecureRandom secureRandom)
    {
        throw new UnsupportedOperationException("Operation not supported");
    }

    protected SecretKey engineGenerateKey()
    {
        if (genSpec != null)
        {
            BCXWingPublicKey pubKey = (BCXWingPublicKey)genSpec.getPublicKey();
            XWingKEMGenerator kemGen = new XWingKEMGenerator(random);

            SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(pubKey.getKeyParams());

            byte[] kemSecret = secEnc.getSecret();
            byte[] kdfSecret = KdfUtil.makeKeyBytes(genSpec, kemSecret);

            try
            {
                SecretKeySpec secretKey = new SecretKeySpec(kdfSecret, genSpec.getKeyAlgorithmName());

                return new SecretKeyWithEncapsulation(secretKey, secEnc.getEncapsulation());
            }
            finally
            {
                try
                {
                    secEnc.destroy();
                }
                catch (DestroyFailedException e)
                {
                    // ignore
                }
            }
        }
        else
        {
            BCXWingPrivateKey privKey = (BCXWingPrivateKey)extSpec.getPrivateKey();
            XWingKEMExtractor kemExt = new XWingKEMExtractor(privKey.getKeyParams());

            byte[] encapsulation = extSpec.getEncapsulation();

            byte[] kemSecret = kemExt.extractSecret(encapsulation);
            byte[] kdfSecret = KdfUtil.makeKeyBytes(extSpec, kemSecret);

            try
            {
                SecretKeySpec secretKey = new SecretKeySpec(kdfSecret, extSpec.getKeyAlgorithmName());

                return new SecretKeyWithEncapsulation(secretKey, encapsulation);
            }
            finally
            {
                Arrays.clear(kdfSecret);
            }
        }
    }
}
