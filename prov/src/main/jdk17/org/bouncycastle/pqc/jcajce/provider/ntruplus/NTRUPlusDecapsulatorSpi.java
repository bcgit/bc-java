package org.bouncycastle.pqc.jcajce.provider.ntruplus;

import javax.crypto.DecapsulateException;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.util.SpiUtil;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKEMExtractor;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class NTRUPlusDecapsulatorSpi
    implements KEMSpi.DecapsulatorSpi
{
    private final KTSParameterSpec parameterSpec;
    private final NTRUPlusKEMExtractor kemExt;

    NTRUPlusDecapsulatorSpi(BCNTRUPlusPrivateKey privateKey, KTSParameterSpec parameterSpec)
    {
        this.parameterSpec = parameterSpec;
        this.kemExt = new NTRUPlusKEMExtractor(privateKey.getKeyParams());
    }

    @Override
    public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
        throws DecapsulateException
    {
        algorithm = SpiUtil.resolveDecapsulateAlgorithm(encapsulation, from, to, algorithm, engineSecretSize(), engineEncapsulationSize(), parameterSpec);

        // NTRUPlusEngine builds its SHAKE instance per call, so one extractor is safe to share
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
