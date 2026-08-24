package org.bouncycastle.pqc.jcajce.provider.hqc;

import java.security.SecureRandom;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;

import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.provider.asymmetric.util.KemSpiUtil;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMGenerator;
/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class HQCEncapsulatorSpi
    implements KEMSpi.EncapsulatorSpi
{
    private final BCHQCPublicKey publicKey;
    private final KTSParameterSpec parameterSpec;
    private final HQCKEMGenerator kemGen;

    HQCEncapsulatorSpi(BCHQCPublicKey publicKey, KTSParameterSpec parameterSpec, SecureRandom random)
    {
        this.publicKey = publicKey;
        this.parameterSpec = parameterSpec;
        this.kemGen = new HQCKEMGenerator(random);
    }

    @Override
    public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm)
    {
        return KemSpiUtil.buildEncapsulated(from, to, algorithm, engineSecretSize(), kemGen, publicKey.getKeyParams(), parameterSpec);
    }

    @Override
    public int engineSecretSize()
    {
        return parameterSpec.getKeySize() / 8;
    }

    @Override
    public int engineEncapsulationSize()
    {
        return publicKey.getKeyParams().getParameters().getEncapsulationLength();
    }
}
