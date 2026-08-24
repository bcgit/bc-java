package org.bouncycastle.jcajce.provider.asymmetric.frodokem;

import javax.crypto.DecapsulateException;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.kems.FrodoKEMExtractor;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.provider.asymmetric.util.KemSpiUtil;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class FrodoKEMDecapsulatorSpi
    implements KEMSpi.DecapsulatorSpi
{
    private final KTSParameterSpec parameterSpec;
    private final FrodoKEMExtractor kemExt;

    FrodoKEMDecapsulatorSpi(BCFrodoKEMPrivateKey privateKey, KTSParameterSpec parameterSpec)
    {
        this.parameterSpec = parameterSpec;
        this.kemExt = new FrodoKEMExtractor(privateKey.getKeyParams());
    }

    @Override
    public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
        throws DecapsulateException
    {
        algorithm = KemSpiUtil.resolveDecapsulateAlgorithm(encapsulation, from, to, algorithm, engineSecretSize(), engineEncapsulationSize(), parameterSpec);

        // FrodoKEMEngine builds its SHAKE instance per call, so one extractor is safe to share
        // across the concurrent decapsulate calls javax.crypto.KEM requires.
        byte[] kemSecret = kemExt.extractSecret(encapsulation);

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
