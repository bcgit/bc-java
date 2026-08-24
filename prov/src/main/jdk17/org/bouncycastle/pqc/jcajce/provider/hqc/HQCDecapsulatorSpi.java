package org.bouncycastle.pqc.jcajce.provider.hqc;

import javax.crypto.DecapsulateException;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.provider.asymmetric.util.KemSpiUtil;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMExtractor;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class HQCDecapsulatorSpi
    implements KEMSpi.DecapsulatorSpi
{
    private final KTSParameterSpec parameterSpec;
    private final HQCKEMExtractor kemExt;

    HQCDecapsulatorSpi(BCHQCPrivateKey privateKey, KTSParameterSpec parameterSpec)
    {
        this.parameterSpec = parameterSpec;
        this.kemExt = new HQCKEMExtractor(privateKey.getKeyParams());
    }

    @Override
    public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
        throws DecapsulateException
    {
        algorithm = KemSpiUtil.resolveDecapsulateAlgorithm(encapsulation, from, to, algorithm, engineSecretSize(), engineEncapsulationSize(), parameterSpec);

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
