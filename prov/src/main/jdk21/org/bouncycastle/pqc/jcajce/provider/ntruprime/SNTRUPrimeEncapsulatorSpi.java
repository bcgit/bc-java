package org.bouncycastle.pqc.jcajce.provider.ntruprime;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMGenerator;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Objects;

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

        SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(publicKey.getKeyParams());

        // TODO: parameters...
        byte[] secret = secEnc.getSecret();
        return new KEM.Encapsulated(new SecretKeySpec(secret, 0, secret.length, algorithm), secEnc.getEncapsulation(), null);
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
