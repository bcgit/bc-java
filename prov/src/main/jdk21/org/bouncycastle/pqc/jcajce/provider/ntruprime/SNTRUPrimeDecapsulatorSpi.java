package org.bouncycastle.pqc.jcajce.provider.ntruprime;

import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor;

import javax.crypto.DecapsulateException;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
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
        byte[] secret = kemExt.extractSecret(encapsulation);
        return new SecretKeySpec(secret, 0, secret.length, algorithm);
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
