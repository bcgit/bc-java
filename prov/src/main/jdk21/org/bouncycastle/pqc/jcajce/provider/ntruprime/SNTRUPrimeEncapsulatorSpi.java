package org.bouncycastle.pqc.jcajce.provider.ntruprime;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMGenerator;
import org.bouncycastle.pqc.jcajce.provider.util.WrapUtil;
import org.bouncycastle.util.Arrays;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Objects;

class SNTRUPrimeEncapsulatorSpi
    implements KEMSpi.EncapsulatorSpi
{
    private final BCSNTRUPrimePublicKey publicKey;
    private final KTSParameterSpec parameterSpec;
    private final SNTRUPrimeKEMGenerator kemGen;


    public SNTRUPrimeEncapsulatorSpi(BCSNTRUPrimePublicKey publicKey, KTSParameterSpec parameterSpec, SecureRandom random)
    {
        this.publicKey = publicKey;
        this.parameterSpec = parameterSpec;

        kemGen = new SNTRUPrimeKEMGenerator(random);
    }

    @Override
    public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm)
    {
        Objects.checkFromToIndex(from, to, engineSecretSize());
        Objects.requireNonNull(algorithm, "null algorithm");

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

        SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(publicKey.getKeyParams());

        byte[] encapsulation = secEnc.getEncapsulation();
        byte[] secret = secEnc.getSecret();

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

                Wrapper kWrap = WrapUtil.getKeyWrapper(spec, secret);
                secretKey = kWrap.wrap(secretKey, 0, secretKey.length);
//                 secretKey = Arrays.concatenate(encapsulation, kWrap.wrap(secretKey, 0, secretKey.length));
            }
            catch (InvalidKeyException e)
            {
                throw new RuntimeException(e);
            }
        }

        return new KEM.Encapsulated(new SecretKeySpec(secretKey, algorithm), encapsulation, parameterSpec.getOtherInfo());

    }

    @Override
    public int engineSecretSize()
    {
        return parameterSpec.getKeySize() / 8;
    }

    @Override
    public int engineEncapsulationSize()
    {
        return publicKey.getKeyParams().getParameters().getRoundedPolynomialBytes() + 32;
    }
}
