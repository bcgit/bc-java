package org.bouncycastle.pqc.jcajce.provider.hqc;

import org.bouncycastle.pqc.jcajce.provider.hqc.BCHQCPrivateKey;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;

import org.bouncycastle.pqc.crypto.hqc.HQCKEMExtractor;
import org.bouncycastle.pqc.jcajce.provider.util.KdfUtil;

import javax.crypto.DecapsulateException;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.util.Arrays;
import java.util.Objects;

public class HQCDecapsulatorSpi
    implements KEMSpi.DecapsulatorSpi
{
    BCHQCPrivateKey privateKey;
    KTSParameterSpec parameterSpec;
    HQCKEMExtractor kemExt;

    public HQCDecapsulatorSpi(BCHQCPrivateKey privateKey, KTSParameterSpec parameterSpec)
    {
        this.privateKey = privateKey;
        this.parameterSpec = parameterSpec;

        this.kemExt = new HQCKEMExtractor(privateKey.getKeyParams());
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