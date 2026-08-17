package org.bouncycastle.jcajce.provider.asymmetric.frodokem;

import java.util.Objects;

import javax.crypto.DecapsulateException;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.kems.FrodoKEMExtractor;
import org.bouncycastle.crypto.params.FrodoKEMPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class FrodoKEMDecapsulatorSpi
    implements KEMSpi.DecapsulatorSpi
{
    private final FrodoKEMPrivateKeyParameters privateKeyParams;
    private final KTSParameterSpec parameterSpec;
    private final int encapsulationLength;

    FrodoKEMDecapsulatorSpi(BCFrodoKEMPrivateKey privateKey, KTSParameterSpec parameterSpec)
    {
        this.privateKeyParams = privateKey.getKeyParams();
        this.parameterSpec = parameterSpec;
        this.encapsulationLength = privateKeyParams.getParameters().getEncapsulationLength();
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

        // A FrodoKEMExtractor holds one FrodoKEMEngine, whose SHAKE digest is mutable state, so a
        // shared extractor is not safe for the concurrent use javax.crypto.KEM requires of a
        // Decapsulator - build one per call, as FrodoKEMCipherSpi.engineUnwrap does.
        byte[] kemSecret = new FrodoKEMExtractor(privateKeyParams).extractSecret(encapsulation);
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
        return encapsulationLength;
    }
}
