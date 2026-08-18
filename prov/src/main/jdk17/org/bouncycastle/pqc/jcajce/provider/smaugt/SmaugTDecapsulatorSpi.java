package org.bouncycastle.pqc.jcajce.provider.smaugt;

import java.util.Objects;

import javax.crypto.DecapsulateException;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTKEMExtractor;
import org.bouncycastle.util.Arrays;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class SmaugTDecapsulatorSpi
    implements KEMSpi.DecapsulatorSpi
{
    private final KTSParameterSpec parameterSpec;
    // The SmaugTEngine an extractor takes from its parameter set carries no mutable state - every
    // field is a static constant and each operation allocates its own buffers - so one extractor is
    // safe to share across the concurrent decapsulate calls javax.crypto.KEM requires.
    private final SmaugTKEMExtractor kemExt;

    SmaugTDecapsulatorSpi(BCSmaugTPrivateKey privateKey, KTSParameterSpec parameterSpec)
    {
        this.parameterSpec = parameterSpec;
        this.kemExt = new SmaugTKEMExtractor(privateKey.getKeyParams());
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

        byte[] kemSecret = kemExt.extractSecret(encapsulation);
        byte[] kdfSecret = KdfUtil.makeKeyBytes(parameterSpec, kemSecret);

        try
        {
            return new SecretKeySpec(kdfSecret, from, to - from, algorithm);
        }
        finally
        {
            Arrays.clear(kdfSecret);
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
        return kemExt.getEncapsulationLength();
    }
}
