package org.bouncycastle.pqc.jcajce.provider.ntruprime;

import java.util.Objects;

import javax.crypto.DecapsulateException;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class SNTRUPrimeDecapsulatorSpi
    implements KEMSpi.DecapsulatorSpi
{
//    private final BCSNTRUPrimePrivateKey privateKey;
    private final KTSParameterSpec parameterSpec;
    private final SNTRUPrimeKEMExtractor kemExt;

    SNTRUPrimeDecapsulatorSpi(BCSNTRUPrimePrivateKey privateKey, KTSParameterSpec parameterSpec)
    {
//        this.privateKey = privateKey;
        this.parameterSpec = parameterSpec;
        this.kemExt = new SNTRUPrimeKEMExtractor(privateKey.getKeyParams());
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
