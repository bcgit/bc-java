package org.bouncycastle.jcajce.provider.asymmetric.xwing;

import java.security.SecureRandom;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;

import org.bouncycastle.jcajce.provider.asymmetric.util.KemSpiUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.xwing.XWingKEMGenerator;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class XWingEncapsulatorSpi
    implements KEMSpi.EncapsulatorSpi
{
    /** draft-connolly-cfrg-xwing-kem: ML-KEM-768 ciphertext (1088) || X25519 ephemeral public key (32). */
    static final int ENCAPSULATION_LENGTH = 1120;

    private final BCXWingPublicKey publicKey;
    private final KTSParameterSpec parameterSpec;
    private final XWingKEMGenerator kemGen;

    XWingEncapsulatorSpi(BCXWingPublicKey publicKey, KTSParameterSpec parameterSpec, SecureRandom random)
    {
        this.publicKey = publicKey;
        this.parameterSpec = parameterSpec;
        this.kemGen = new XWingKEMGenerator(random);
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
        return ENCAPSULATION_LENGTH;
    }
}
