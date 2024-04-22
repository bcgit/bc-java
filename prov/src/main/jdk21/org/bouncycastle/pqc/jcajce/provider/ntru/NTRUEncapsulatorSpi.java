package org.bouncycastle.pqc.jcajce.provider.ntru;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.ntru.NTRUKEMGenerator;
import org.bouncycastle.pqc.jcajce.provider.Util;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

public class NTRUEncapsulatorSpi
    implements KEMSpi.EncapsulatorSpi
{
    private final BCNTRUPublicKey publicKey;
    private final KTSParameterSpec parameterSpec;
    private final NTRUKEMGenerator kemGen;

    public NTRUEncapsulatorSpi(BCNTRUPublicKey publicKey, KTSParameterSpec parameterSpec, SecureRandom random)
    {
        this.publicKey = publicKey;
        this.parameterSpec = parameterSpec;

        this.kemGen = new NTRUKEMGenerator(random);
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

        byte[] secretKey;

        if (useKDF)
        {
            try
            {
                secret = Util.makeKeyBytes(parameterSpec, secret);
            }
            catch (InvalidKeyException e)
            {
                throw new IllegalStateException(e);
            }
        }

        secretKey = Arrays.copyOfRange(secret, from, to);

        return new KEM.Encapsulated(new SecretKeySpec(secretKey, algorithm), encapsulation, null); //TODO: DER encoding for params

    }

    @Override
    public int engineSecretSize()
    {
        return parameterSpec.getKeySize() / 8;
    }

    @Override
    public int engineEncapsulationSize()
    {
        //TODO: Maybe make parameterSet public or add getEncapsulationSize() in NTRUKEMGenerator.java
        switch (publicKey.getKeyParams().getParameters().getName())
        {
            case "ntruhps2048509":
                return 699;
            case "ntruhps2048677":
                return 930;
            case "ntruhps4096821":
                return 1230;
            case "ntruhps40961229":
                return 1843;
            case "ntruhrss701":
                return 1138;
            case "ntruhrss1373":
                return 2401;
            default:
                return -1;
        }
    }
}
