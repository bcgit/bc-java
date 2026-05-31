package org.bouncycastle.pqc.crypto.qruov;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class QRUOVKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private QRUOVParameters params;
    private SecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        this.params = ((QRUOVKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        int seedLen = params.getSeedLen();
        byte[] seedSk = new byte[seedLen];
        byte[] seedPk = new byte[seedLen];
        random.nextBytes(seedSk);
        random.nextBytes(seedPk);

        QRUOVEngine engine = new QRUOVEngine(params);
        int m = params.getM();
        int M = params.getBigM();
        int L = params.getL();
        byte[][][][] P3 = new byte[m][M][L][M];
        engine.keyGen(seedSk, seedPk, P3);

        // sk = seed_sk || seed_pk
        byte[] sk = new byte[params.getPrivateKeyBytes()];
        long[] pb = new long[]{0L};
        engine.storeSeed(seedSk, sk, pb);
        engine.storeSeed(seedPk, sk, pb);

        // pk = seed_pk || pack(P3)
        byte[] pk = new byte[params.getPublicKeyBytes()];
        pb[0] = 0L;
        engine.storeSeed(seedPk, pk, pb);
        engine.storeP3(P3, pk, pb);

        return new AsymmetricCipherKeyPair(
            new QRUOVPublicKeyParameters(params, pk),
            new QRUOVPrivateKeyParameters(params, sk));
    }
}
