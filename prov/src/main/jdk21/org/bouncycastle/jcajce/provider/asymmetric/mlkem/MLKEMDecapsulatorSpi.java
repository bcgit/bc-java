package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPrivateKey;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.jcajce.provider.util.KdfUtil;

import javax.crypto.DecapsulateException;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Objects;

public class MLKEMDecapsulatorSpi
    implements KEMSpi.DecapsulatorSpi
{
    BCMLKEMPrivateKey privateKey;
    KTSParameterSpec parameterSpec;
    MLKEMExtractor kemExt;

    public MLKEMDecapsulatorSpi(BCMLKEMPrivateKey privateKey, KTSParameterSpec parameterSpec)
    {
        this.privateKey = privateKey;
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

        // if algorithm is Generic then use parameterSpec to wrap key
        if (!parameterSpec.getKeyAlgorithmName().equals("Generic") &&
                algorithm.equals("Generic"))
        {
            algorithm = parameterSpec.getKeyAlgorithmName();
        }

        // check spec algorithm mismatch provided algorithm
        if (!parameterSpec.getKeyAlgorithmName().equals("Generic") &&
                !parameterSpec.getKeyAlgorithmName().equals(algorithm))
        {
            throw new UnsupportedOperationException(parameterSpec.getKeyAlgorithmName() + " does not match " + algorithm);
        }

        // Only use KDF when ktsParameterSpec is provided
        // Considering any ktsParameterSpec with "Generic" as ktsParameterSpec not provided
        boolean useKDF = parameterSpec.getKdfAlgorithm() != null;

        byte[] secret = kemExt.extractSecret(encapsulation);
        byte[] secretKey = Arrays.copyOfRange(KdfUtil.makeKeyBytes(parameterSpec, secret), from, to);

        return new SecretKeySpec(secretKey, algorithm);
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
