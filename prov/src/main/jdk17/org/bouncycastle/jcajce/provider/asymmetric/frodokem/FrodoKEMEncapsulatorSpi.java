package org.bouncycastle.jcajce.provider.asymmetric.frodokem;

import java.security.SecureRandom;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;

import org.bouncycastle.crypto.kems.FrodoKEMGenerator;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.util.SpiUtil;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class FrodoKEMEncapsulatorSpi
    implements KEMSpi.EncapsulatorSpi
{
    private final BCFrodoKEMPublicKey publicKey;
    private final KTSParameterSpec parameterSpec;
    private final FrodoKEMGenerator kemGen;
    private final int encapsulationLength;

    FrodoKEMEncapsulatorSpi(BCFrodoKEMPublicKey publicKey, KTSParameterSpec parameterSpec, SecureRandom random)
    {
        this.publicKey = publicKey;
        this.parameterSpec = parameterSpec;
        this.kemGen = new FrodoKEMGenerator(random);
        this.encapsulationLength = publicKey.getKeyParams().getParameters().getEncapsulationLength();
    }

    @Override
    public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm)
    {
        return SpiUtil.buildEncapsulated(from, to, algorithm, engineSecretSize(), kemGen, publicKey.getKeyParams(), parameterSpec);
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
