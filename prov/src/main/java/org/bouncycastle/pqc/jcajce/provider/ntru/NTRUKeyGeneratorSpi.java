package org.bouncycastle.pqc.jcajce.provider.ntru;

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
import org.bouncycastle.jcajce.spec.KEMKDFSpec;
import org.bouncycastle.pqc.crypto.ntru.NTRUKEMExtractor;
import org.bouncycastle.pqc.crypto.ntru.NTRUKEMGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

public class NTRUKeyGeneratorSpi
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
            KEMGenerateSpec spec = (KEMGenerateSpec)algorithmParameterSpec;
            if (!(spec.getPublicKey() instanceof BCNTRUPublicKey))
            {
                throw new InvalidAlgorithmParameterException("unsupported public key: NTRU public key required");
            }
            checkSpec(spec, ((BCNTRUPublicKey)spec.getPublicKey()).getKeyParams().getParameters());

            this.genSpec = spec;
            this.extSpec = null;
        }
        else if (algorithmParameterSpec instanceof KEMExtractSpec)
        {
            KEMExtractSpec spec = (KEMExtractSpec)algorithmParameterSpec;
            if (!(spec.getPrivateKey() instanceof BCNTRUPrivateKey))
            {
                throw new InvalidAlgorithmParameterException("unsupported private key: NTRU private key required");
            }
            checkSpec(spec, ((BCNTRUPrivateKey)spec.getPrivateKey()).getKeyParams().getParameters());

            this.genSpec = null;
            this.extSpec = spec;
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unknown spec");
        }
    }

    // with no KDF the key is taken from the front of the shared secret, so it cannot be longer than the secret
    private static void checkSpec(KEMKDFSpec spec, NTRUParameters parameters)
        throws InvalidAlgorithmParameterException
    {
        KdfUtil.checkKemKdfSpec(spec, parameters.getName(), parameters.getSessionKeySize());
    }

    protected void engineInit(int i, SecureRandom secureRandom)
    {
        throw new UnsupportedOperationException("Operation not supported");
    }

    protected SecretKey engineGenerateKey()
    {
        if (genSpec != null)
        {
            BCNTRUPublicKey pubKey = (BCNTRUPublicKey)genSpec.getPublicKey();
            NTRUKEMGenerator kemGen = new NTRUKEMGenerator(random);

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
            BCNTRUPrivateKey privKey = (BCNTRUPrivateKey)extSpec.getPrivateKey();
            NTRUKEMExtractor kemExt = new NTRUKEMExtractor(privKey.getKeyParams());

            byte[] encapsulation = extSpec.getEncapsulation();
            byte[] keyBytes = KdfUtil.makeKeyBytes(extSpec, kemExt.extractSecret(encapsulation));

            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(keyBytes, extSpec.getKeyAlgorithmName()), encapsulation);

            Arrays.clear(keyBytes);

            return rv;
        }
    }
}
