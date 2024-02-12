package org.bouncycastle.pqc.jcajce.provider.ntruprime;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMGenerator;
import org.bouncycastle.pqc.jcajce.provider.util.WrapUtil;
import org.bouncycastle.util.Arrays;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Objects;

import static org.bouncycastle.pqc.jcajce.provider.Util.makeKeyBytes;

class SNTRUPrimeEncapsulatorSpi
    implements KEMSpi.EncapsulatorSpi
{
    private final BCSNTRUPrimePublicKey publicKey;
    private final KTSParameterSpec parameterSpec;
    private final SecureRandom random;
    private final SNTRUPrimeKEMGenerator kemGen;


    public SNTRUPrimeEncapsulatorSpi(BCSNTRUPrimePublicKey publicKey, KTSParameterSpec parameterSpec, SecureRandom random)
    {
        this.publicKey = publicKey;
        this.parameterSpec = parameterSpec;
        this.random = random;

        kemGen = new SNTRUPrimeKEMGenerator(random);
    }

    @Override
    public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm)
    {
        Objects.checkFromToIndex(from, to, engineEncapsulationSize());
        Objects.requireNonNull(algorithm, "null algorithm");

        KTSParameterSpec.Builder builder = new KTSParameterSpec.Builder(parameterSpec.getKeyAlgorithmName(), parameterSpec.getKeySize());

        if (!algorithm.equals("Generic"))
        {
            //TODO:
//            builder.withKdfAlgorithm(AlgorithmIdentifier.getInstance(algorithm));
        }
        KTSParameterSpec spec = builder.build();

        SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(publicKey.getKeyParams());

        byte[] encapsulation = secEnc.getEncapsulation();
        byte[] secret = secEnc.getSecret();

        byte[] kdfKey = Arrays.copyOfRange(secret, from, to);

        try
        {
            return new KEM.Encapsulated(new SecretKeySpec(makeKeyBytes(spec, kdfKey), algorithm), encapsulation , null);
        }
        catch (InvalidKeyException e)
        {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int engineSecretSize()
    {
        return publicKey.getKeyParams().getParameters().getSessionKeySize() / 8;
    }

    @Override
    public int engineEncapsulationSize()
    {
        return publicKey.getKeyParams().getParameters().getRoundedPolynomialBytes() + 32;
    }
}
