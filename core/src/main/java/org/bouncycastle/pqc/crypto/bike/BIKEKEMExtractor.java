package org.bouncycastle.pqc.crypto.bike;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.util.Arrays;

public class BIKEKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private BIKEEngine engine;

    private BIKEKeyParameters key;

    public BIKEKEMExtractor(BIKEPrivateKeyParameters privParams)
    {
        this.key = privParams;
        initCipher(key.getParameters());
    }

    private void initCipher(BIKEParameters param)
    {
        engine = param.getEngine();
    }


    @Override
    public byte[] extractSecret(byte[] encapsulation)
    {
        byte[] session_key = new byte[engine.getSessionKeySize()];
        BIKEPrivateKeyParameters secretKey = (BIKEPrivateKeyParameters)key;

        // Extract c0, c1 from encapsulation c
        byte[] c0 = Arrays.copyOfRange(encapsulation, 0, secretKey.getParameters().getRByte());
        byte[] c1 = Arrays.copyOfRange(encapsulation, secretKey.getParameters().getRByte(), encapsulation.length);

        byte[] h0 = secretKey.getH0();
        byte[] h1 = secretKey.getH1();
        byte[] sigma = secretKey.getSigma();

        engine.decaps(session_key, h0, h1, sigma, c0, c1);
        return Arrays.copyOfRange(session_key, 0, key.getParameters().getSessionKeySize() / 8);
    }

    public int getEncapsulationLength()
    {
        return key.getParameters().getRByte() + key.getParameters().getLByte();
    }
}
