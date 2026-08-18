package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.security.SecureRandom;
import java.util.Objects;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.SM9KEMGenerator;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class SM9EncapsulatorSpi
    implements KEMSpi.EncapsulatorSpi
{
    private final BCSM9EncPublicKey publicKey;
    private final KTSParameterSpec parameterSpec;
    private final SM9KEMGenerator kemGen;

    SM9EncapsulatorSpi(BCSM9EncPublicKey publicKey, KTSParameterSpec parameterSpec, SecureRandom random)
    {
        this.publicKey = publicKey;
        this.parameterSpec = parameterSpec;
        // without an external KDF the mechanism's own GM/T 0044.4 KDF produces the shared
        // secret at the requested size; with one it first produces a 256-bit shared secret.
        this.kemGen = new SM9KEMGenerator(
            parameterSpec.getKdfAlgorithm() == null ? parameterSpec.getKeySize() : 256, random);
    }

    @Override
    public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm)
    {
        Objects.checkFromToIndex(from, to, engineSecretSize());
        Objects.requireNonNull(algorithm, "null algorithm");

        algorithm = KdfUtil.resolveAlgorithm(parameterSpec, algorithm);

        SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(publicKey.getKeyParameters());

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
        // C = [r]Q_B of G1, encoded x || y (GM/T 0044.4).
        return 64;
    }
}
