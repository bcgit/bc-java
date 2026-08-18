package org.bouncycastle.pqc.jcajce.provider.smaugt;

import java.security.SecureRandom;
import java.util.Objects;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTKEMGenerator;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class SmaugTEncapsulatorSpi
    implements KEMSpi.EncapsulatorSpi
{
    private final BCSmaugTPublicKey publicKey;
    private final KTSParameterSpec parameterSpec;
    private final SmaugTKEMGenerator kemGen;
    private final int encapsulationLength;

    SmaugTEncapsulatorSpi(BCSmaugTPublicKey publicKey, KTSParameterSpec parameterSpec, SecureRandom random)
    {
        this.publicKey = publicKey;
        this.parameterSpec = parameterSpec;
        this.kemGen = new SmaugTKEMGenerator(random);
        this.encapsulationLength = publicKey.getKeyParams().getParameters().getEncapsulationLength();
    }

    @Override
    public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm)
    {
        Objects.checkFromToIndex(from, to, engineSecretSize());
        Objects.requireNonNull(algorithm, "null algorithm");

        algorithm = KdfUtil.resolveAlgorithm(parameterSpec, algorithm);

        SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(publicKey.getKeyParams());

        try
        {
            // getEncapsulation()/getSecret() hand back clones, so the originals have to be
            // destroyed as well - KdfUtil.makeSecretKey only clears the secret clone it is passed.
            byte[] encapsulation = secEnc.getEncapsulation();

            SecretKey secretKey = KdfUtil.makeSecretKey(parameterSpec, secEnc.getSecret(),
                from, to, algorithm);

            return new KEM.Encapsulated(secretKey, encapsulation, null);
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

    @Override
    public int engineSecretSize()
    {
        return parameterSpec.getKeySize() / 8;
    }

    @Override
    public int engineEncapsulationSize()
    {
        return encapsulationLength;
    }
}
