package org.bouncycastle.pqc.jcajce.provider.ntruprime;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
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
import org.bouncycastle.jcajce.spec.KEMKDFSpec;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

public class NTRULPRimeKeyGeneratorSpi
        extends KeyGeneratorSpi
{
    private KEMGenerateSpec genSpec;
    private SecureRandom random;
    private KEMExtractSpec extSpec;

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
            checkSpec((KEMGenerateSpec)algorithmParameterSpec, ((KEMGenerateSpec)algorithmParameterSpec).getPublicKey());
            this.genSpec = (KEMGenerateSpec)algorithmParameterSpec;
            this.extSpec = null;
        }
        else if (algorithmParameterSpec instanceof KEMExtractSpec)
        {
            this.genSpec = null;
            checkSpec((KEMExtractSpec)algorithmParameterSpec, ((KEMExtractSpec)algorithmParameterSpec).getPrivateKey());
            this.extSpec = (KEMExtractSpec)algorithmParameterSpec;
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

    // the key's parameter set gives the size of the shared secret a spec with no KDF is limited to
    private static void checkSpec(KEMKDFSpec spec, Key key)
        throws InvalidAlgorithmParameterException
    {
        NTRULPRimeParameters parameters;
        if (key instanceof BCNTRULPRimePublicKey)
        {
            parameters = ((BCNTRULPRimePublicKey)key).getKeyParams().getParameters();
        }
        else if (key instanceof BCNTRULPRimePrivateKey)
        {
            parameters = ((BCNTRULPRimePrivateKey)key).getKeyParams().getParameters();
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unsupported key: NTRU LPRime key required");
        }

        KdfUtil.checkKemKdfSpec(spec, parameters.getName(), parameters.getSessionKeySize());
    }

    protected SecretKey engineGenerateKey()
    {
        if (genSpec != null)
        {
            BCNTRULPRimePublicKey pubKey = (BCNTRULPRimePublicKey)genSpec.getPublicKey();
            NTRULPRimeKEMGenerator kemGen = new NTRULPRimeKEMGenerator(random);

            SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(pubKey.getKeyParams());

            byte[] keyBytes = KdfUtil.makeKeyBytes(genSpec, secEnc.getSecret());

            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(keyBytes, genSpec.getKeyAlgorithmName()), secEnc.getEncapsulation());

            Arrays.clear(keyBytes);

            try
            {
                secEnc.destroy();
            }
            catch (DestroyFailedException e)
            {
                throw Exceptions.illegalStateException("key cleanup failed", e);
            }

            return rv;
        }
        else
        {
            BCNTRULPRimePrivateKey privKey = (BCNTRULPRimePrivateKey)extSpec.getPrivateKey();
            NTRULPRimeKEMExtractor kemExt = new NTRULPRimeKEMExtractor(privKey.getKeyParams());

            byte[] encapsulation = extSpec.getEncapsulation();
            byte[] secret = kemExt.extractSecret(encapsulation);

            byte[] keyBytes = KdfUtil.makeKeyBytes(extSpec, secret);

            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(keyBytes, extSpec.getKeyAlgorithmName()), encapsulation);

            Arrays.clear(keyBytes);

            return rv;
        }
    }
}
