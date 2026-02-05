package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.util.Objects;

import javax.crypto.DecapsulateException;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.jcajce.provider.util.KdfUtil;
import org.bouncycastle.util.Arrays;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class MLKEMDecapsulatorSpi
    implements KEMSpi.DecapsulatorSpi
{
//    private final BCMLKEMPrivateKey privateKey;
    private final KTSParameterSpec parameterSpec;
    private final MLKEMExtractor kemExt;

    MLKEMDecapsulatorSpi(BCMLKEMPrivateKey privateKey, KTSParameterSpec parameterSpec)
    {
//        this.privateKey = privateKey;
        this.parameterSpec = parameterSpec;
        this.kemExt = new MLKEMExtractor(privateKey.getKeyParams());
    }

    @Override
    public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm) throws DecapsulateException
    {
        Objects.checkFromToIndex(from, to, engineSecretSize());
        Objects.requireNonNull(algorithm, "null algorithm");
        Objects.requireNonNull(encapsulation, "null encapsulation");

        if (encapsulation.length != engineEncapsulationSize())
        {
            throw new DecapsulateException("incorrect encapsulation size");
        }

        String keyAlgName = parameterSpec.getKeyAlgorithmName();
        if (!"Generic".equals(keyAlgName))
        {
            // if algorithm is Generic then use parameterSpec to wrap key
            if ("Generic".equals(algorithm))
            {
                algorithm = keyAlgName;
            }
            // check spec algorithm mismatch provided algorithm
            else if (!algorithm.equals(keyAlgName))
            {
                throw new UnsupportedOperationException(keyAlgName + " does not match " + algorithm);
            }
        }

        byte[] kemSecret = kemExt.extractSecret(encapsulation);
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
        return kemExt.getEncapsulationLength();
    }
}
