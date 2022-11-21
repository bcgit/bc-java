package org.bouncycastle.pqc.crypto.sike;

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;

public class SIKEKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private SIKEEngine engine;

    private SIKEKeyParameters key;

    public SIKEKEMExtractor(SIKEPrivateKeyParameters privParams)
    {
        // -DM System.err.println
        System.err.println("WARNING: the SIKE algorithm is only for research purposes, insecure");
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("SIKEKEM", 0, privParams, CryptoServicePurpose.DECRYPTION));

        this.key = privParams;
        initCipher(key.getParameters());
    }

    private void initCipher(SIKEParameters param)
    {
        engine = param.getEngine();
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        return extractSecret(encapsulation, engine.getDefaultSessionKeySize());
    }

    public byte[] extractSecret(byte[] encapsulation, int sessionKeySizeInBits)
    {
        // -DM System.err.println
        System.err.println("WARNING: the SIKE algorithm is only for research purposes, insecure");
        byte[] session_key = new byte[sessionKeySizeInBits / 8];
        engine.crypto_kem_dec(session_key, encapsulation, ((SIKEPrivateKeyParameters)key).getPrivateKey());
        return session_key;
    }

    public int getEncapsulationLength()
    {
        return engine.getCipherTextSize();
    }
}
