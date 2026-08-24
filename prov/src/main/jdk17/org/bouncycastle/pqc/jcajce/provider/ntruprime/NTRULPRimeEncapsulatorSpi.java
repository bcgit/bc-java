package org.bouncycastle.pqc.jcajce.provider.ntruprime;

import java.security.SecureRandom;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;

import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.provider.asymmetric.util.KemSpiUtil;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKEMGenerator;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class NTRULPRimeEncapsulatorSpi
    implements KEMSpi.EncapsulatorSpi
{
    private final BCNTRULPRimePublicKey publicKey;
    private final KTSParameterSpec parameterSpec;
    private final NTRULPRimeKEMGenerator kemGen;
    private final int encapsulationLength;

    NTRULPRimeEncapsulatorSpi(BCNTRULPRimePublicKey publicKey, KTSParameterSpec parameterSpec, SecureRandom random)
    {
        this.publicKey = publicKey;
        this.parameterSpec = parameterSpec;
        this.kemGen = new NTRULPRimeKEMGenerator(random);
        this.encapsulationLength = publicKey.getKeyParams().getParameters().getEncapsulationLength();
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
        return encapsulationLength;
    }
}
