package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.security.SecureRandom;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;

import org.bouncycastle.crypto.kems.SM9KEMGenerator;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.util.SpiUtil;

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
        return SpiUtil.buildEncapsulated(from, to, algorithm, engineSecretSize(), kemGen, publicKey.getKeyParameters(), parameterSpec);
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
