package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.util.Arrays;

public class HQCKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private HQCEngine engine;

    private final HQCKeyParameters key;

    public HQCKEMExtractor(HQCPrivateKeyParameters privParams)
    {
        this.key = privParams;
        initCipher(key.getParameters());
    }

    private void initCipher(HQCParameters param)
    {
        engine = param.getEngine();
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        byte[] session_key = new byte[64];
        HQCPrivateKeyParameters secretKey = (HQCPrivateKeyParameters)key;
        byte[] sk = secretKey.getPrivateKey();

        engine.decaps(session_key, encapsulation, sk);

        return Arrays.copyOfRange(session_key, 0, 32);
    }

    public int getEncapsulationLength()
    {         // Hash + salt
        return key.getParameters().getN_BYTES() + key.getParameters().getN1N2_BYTES() + 16;
    }
}
