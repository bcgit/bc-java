package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.security.SecureRandom;
import java.util.Objects;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.jcajce.provider.util.KdfUtil;
import org.bouncycastle.util.Arrays;

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

        SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(publicKey.getKeyParams());

        byte[] encapsulation = secEnc.getEncapsulation();

        byte[] kemSecret = secEnc.getSecret();
        byte[] kdfSecret = KdfUtil.makeKeyBytes(parameterSpec, kemSecret);

        try
        {
            SecretKey secretKey = new SecretKeySpec(kdfSecret, from, to - from, algorithm);
            return new KEM.Encapsulated(secretKey, encapsulation, null); //TODO: DER encoding for params
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
