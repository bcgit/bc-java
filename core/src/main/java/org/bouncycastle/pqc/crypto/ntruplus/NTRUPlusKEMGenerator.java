package org.bouncycastle.pqc.crypto.ntruplus;

import java.security.SecureRandom;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;

public class NTRUPlusKEMGenerator
    implements EncapsulatedSecretGenerator
{
    private final SecureRandom sr;

    public NTRUPlusKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    @Override
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        NTRUPlusPublicKeyParameters key = (NTRUPlusPublicKeyParameters)recipientKey;
        NTRUPlusParameters params = key.getParameters();
        byte[] ct = new byte[params.getCiphertextBytes()];
        byte[] ss = new byte[NTRUPlusEngine.SSBytes];
        NTRUPlusEngine engine = new NTRUPlusEngine(params);
        byte[] coins = new byte[params.getN() >> 3];
        sr.nextBytes(coins);
        engine.crypto_kem_enc_derand(ct, 0, ss,0, key.getEncoded(), 0, coins, 0);
        return new SecretWithEncapsulationImpl(ss, ct);
    }
}
