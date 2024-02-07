package org.bouncycastle.pqc.jcajce.provider.ntruprime;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor;
import org.bouncycastle.pqc.jcajce.provider.util.WrapUtil;
import org.bouncycastle.util.Arrays;

import javax.crypto.DecapsulateException;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

import static org.bouncycastle.pqc.jcajce.provider.Util.makeKeyBytes;

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

        KTSParameterSpec.Builder builder = new KTSParameterSpec.Builder(parameterSpec.getKeyAlgorithmName(), parameterSpec.getKeySize());

        if (!algorithm.equals("Generic"))
        {
            //TODO:
//            builder.withKdfAlgorithm(AlgorithmIdentifier.getInstance(algorithm));
        }
        KTSParameterSpec spec = builder.build();

        byte[] secret = kemExt.extractSecret(encapsulation);

        byte[] kdfKey = Arrays.copyOfRange(secret, from, to);

        try
        {
            return new SecretKeySpec(makeKeyBytes(spec, kdfKey), algorithm);
        }
        catch (InvalidKeyException e)
        {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int engineSecretSize()
    {
        return privateKey.getKeyParams().getParameters().getSessionKeySize() / 8;
    }

    @Override
    public int engineEncapsulationSize()
    {
        return kemExt.getEncapsulationLength();
    }
}
