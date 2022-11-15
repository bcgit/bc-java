package org.bouncycastle.pqc.crypto.hqc;

import java.security.SecureRandom;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;
import org.bouncycastle.util.Arrays;

public class HQCKEMGenerator
    implements EncapsulatedSecretGenerator
{
    private final SecureRandom sr;

    public HQCKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        HQCPublicKeyParameters key = (HQCPublicKeyParameters)recipientKey;
        HQCEngine engine = key.getParameters().getEngine();

        byte[] K = new byte[key.getParameters().getSHA512_BYTES()];
        byte[] u = new byte[key.getParameters().getN_BYTES()];
        byte[] v = new byte[key.getParameters().getN1N2_BYTES()];
        byte[] d = new byte[key.getParameters().getSHA512_BYTES()];
        byte[] salt = new byte[key.getParameters().getSALT_SIZE_BYTES()];
        byte[] pk = key.getPublicKey();
        byte[] seed = new byte[48];

        sr.nextBytes(seed);

        engine.encaps(u, v, K, d, pk, seed, salt);

        byte[] cipherText = Arrays.concatenate(u, v, d, salt);

        return new SecretWithEncapsulationImpl(Arrays.copyOfRange(K, 0, key.getParameters().getK()), cipherText);
    }
}
