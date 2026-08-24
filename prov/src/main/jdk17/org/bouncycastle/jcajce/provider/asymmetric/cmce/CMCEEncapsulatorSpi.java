package org.bouncycastle.jcajce.provider.asymmetric.cmce;

import java.security.SecureRandom;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;

import org.bouncycastle.crypto.kems.CMCEKEMGenerator;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.provider.asymmetric.util.KemSpiUtil;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class CMCEEncapsulatorSpi
    implements KEMSpi.EncapsulatorSpi
{
    private final BCCMCEPublicKey publicKey;
    private final KTSParameterSpec parameterSpec;
    private final CMCEKEMGenerator kemGen;
    private final int encapsulationLength;

    CMCEEncapsulatorSpi(BCCMCEPublicKey publicKey, KTSParameterSpec parameterSpec, SecureRandom random)
    {
        this.publicKey = publicKey;
        this.parameterSpec = parameterSpec;
        this.kemGen = new CMCEKEMGenerator(random);
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
