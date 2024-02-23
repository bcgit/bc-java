package org.bouncycastle.pqc.jcajce.provider.ntruprime;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor;
import org.bouncycastle.pqc.jcajce.provider.util.WrapUtil;
import org.bouncycastle.util.Arrays;

import javax.crypto.DecapsulateException;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.util.Objects;

class SNTRUPrimeDecapsulatorSpi
    implements KEMSpi.DecapsulatorSpi
{
    BCSNTRUPrimePrivateKey privateKey;
    KTSParameterSpec parameterSpec;

    SNTRUPrimeKEMExtractor kemExt;

    public SNTRUPrimeDecapsulatorSpi(BCSNTRUPrimePrivateKey privateKey, KTSParameterSpec parameterSpec)
    {
        this.privateKey = privateKey;
        this.parameterSpec = parameterSpec;

        kemExt = new SNTRUPrimeKEMExtractor(privateKey.getKeyParams());
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
        boolean wrapKey = !(parameterSpec.getKeyAlgorithmName().equals("Generic") && algorithm.equals("Generic"));

        byte[] secret = kemExt.extractSecret(encapsulation);
        byte[] secretKey = Arrays.copyOfRange(secret, from, to);

        if (wrapKey)
        {
            try
            {
                KTSParameterSpec spec = parameterSpec;
                // Generate a new ktsParameterSpec if spec is generic but algorithm is not generic
                if (parameterSpec.getKeyAlgorithmName().equals("Generic"))
                {
                    spec = new KTSParameterSpec.Builder(algorithm, secretKey.length * 8).withNoKdf().build();
                }

                Wrapper kWrap = WrapUtil.getKeyUnwrapper(spec, secretKey);
                secretKey = kWrap.unwrap(secretKey, 0, secretKey.length);

            }
            catch (InvalidCipherTextException e)
            {
                throw new RuntimeException(e);
            }
            catch (InvalidKeyException e)
            {
                throw new RuntimeException(e);
            }

        }
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
