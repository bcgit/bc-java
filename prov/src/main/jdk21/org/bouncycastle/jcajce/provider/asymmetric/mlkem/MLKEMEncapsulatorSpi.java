package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPublicKey;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.jcajce.provider.util.KdfUtil;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

public class MLKEMEncapsulatorSpi
    implements KEMSpi.EncapsulatorSpi
{
    private final BCMLKEMPublicKey publicKey;
    private final KTSParameterSpec parameterSpec;
    private final MLKEMGenerator kemGen;

    public MLKEMEncapsulatorSpi(BCMLKEMPublicKey publicKey, KTSParameterSpec parameterSpec, SecureRandom random)
    {
        this.publicKey = publicKey;
        this.parameterSpec = parameterSpec;

        this.kemGen = new MLKEMGenerator(random);
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
        boolean useKDF = parameterSpec.getKdfAlgorithm() != null;

        SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(publicKey.getKeyParams());

        byte[] encapsulation = secEnc.getEncapsulation();
        byte[] secret = secEnc.getSecret();
        byte[] secretKey = Arrays.copyOfRange(KdfUtil.makeKeyBytes(parameterSpec, secret), from, to);

        return new KEM.Encapsulated(new SecretKeySpec(secretKey, algorithm), encapsulation, null); //TODO: DER encoding for params    }
    }

    @Override
    public int engineSecretSize()
    {
        return parameterSpec.getKeySize() / 8;
    }


    @Override
    public int engineEncapsulationSize()
    {
        //TODO: Maybe make parameterSet public or add getEncapsulationSize() in KEMGenerator.java
        switch (publicKey.getKeyParams().getParameters().getName())
        {
            case "ML-KEM-512":
                return 768;
            case "ML-KEM-768":
                return 1088;
            case "ML-KEM-1024":
                return 1568;
            default:
                return -1;
        }
    }
}
