package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.util.Objects;

import javax.crypto.DecapsulateException;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.kems.SM9KEMExtractor;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class SM9DecapsulatorSpi
    implements KEMSpi.DecapsulatorSpi
{
    private final KTSParameterSpec parameterSpec;
    private final SM9KEMExtractor kemExt;

    SM9DecapsulatorSpi(BCSM9EncPrivateKey privateKey, KTSParameterSpec parameterSpec)
    {
        this.parameterSpec = parameterSpec;
        // without an external KDF the mechanism's own GM/T 0044.4 KDF produces the shared
        // secret at the requested size; with one it first produces a 256-bit shared secret.
        this.kemExt = new SM9KEMExtractor(privateKey.getKeyParameters(),
            parameterSpec.getKdfAlgorithm() == null ? parameterSpec.getKeySize() : 256);
    }

    @Override
    public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
        throws DecapsulateException
    {
        Objects.checkFromToIndex(from, to, engineSecretSize());
        Objects.requireNonNull(algorithm, "null algorithm");
        Objects.requireNonNull(encapsulation, "null encapsulation");

        if (encapsulation.length != engineEncapsulationSize())
        {
            throw new DecapsulateException("incorrect encapsulation size");
        }

        algorithm = KdfUtil.resolveAlgorithm(parameterSpec, algorithm);

        byte[] kemSecret;
        try
        {
            kemSecret = kemExt.extractSecret(encapsulation);
        }
        catch (IllegalArgumentException e)
        {
            // e.g. the encapsulation is not a valid point of G1
            throw new DecapsulateException(e.getMessage(), e);
        }

        return KdfUtil.makeSecretKey(parameterSpec, kemSecret, from, to, algorithm);
    }

    @Override
    public int engineSecretSize()
    {
        return parameterSpec.getKeySize() / 8;
    }

    @Override
    public int engineEncapsulationSize()
    {
        return kemExt.getEncapsulationLength();
    }
}
