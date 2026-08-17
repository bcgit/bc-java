package org.bouncycastle.jcajce.provider.asymmetric.cmce;

import java.security.SecureRandom;
import java.util.Objects;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.CMCEKEMGenerator;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class CMCEEncapsulatorSpi
    implements KEMSpi.EncapsulatorSpi
{
    private final BCCMCEPublicKey publicKey;
    private final KTSParameterSpec parameterSpec;
    private final CMCEKEMGenerator kemGen;
    private final int encapsulationLength;

    CMCEEncapsulatorSpi(BCCMCEPublicKey publicKey, KTSParameterSpec parameterSpec, SecureRandom random)
    {
        this.publicKey = publicKey;
        this.parameterSpec = parameterSpec;
        this.kemGen = new CMCEKEMGenerator(random);
        this.encapsulationLength = publicKey.getKeyParams().getParameters().getEncapsulationLength();
    }

    @Override
    public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm)
    {
        Objects.checkFromToIndex(from, to, engineSecretSize());
        Objects.requireNonNull(algorithm, "null algorithm");

        algorithm = KdfUtil.resolveAlgorithm(parameterSpec, algorithm);

        SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(publicKey.getKeyParams());

        byte[] kdfSecret = null;
        try
        {
            // getEncapsulation()/getSecret() hand back clones, so the originals have to be
            // destroyed as well - KdfUtil.makeKeyBytes only clears the secret clone it is passed.
            byte[] encapsulation = secEnc.getEncapsulation();

            kdfSecret = KdfUtil.makeKeyBytes(parameterSpec, secEnc.getSecret());

            SecretKey secretKey = new SecretKeySpec(kdfSecret, from, to - from, algorithm);
            return new KEM.Encapsulated(secretKey, encapsulation, null);
        }
        finally
        {
            Arrays.clear(kdfSecret);
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
