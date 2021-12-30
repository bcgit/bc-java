package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;

public class CMCEKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private CMCEEngine engine;

    private CMCEKeyParameters key;

    public CMCEKEMExtractor(CMCEPrivateKeyParameters privParams)
    {
        this.key = privParams;
        initCipher(key.getParameters());
    }
    
    private void initCipher(CMCEParameters param)
    {
        engine = param.getEngine();
        CMCEPrivateKeyParameters privateParams = (CMCEPrivateKeyParameters) key;
        if(privateParams.getPrivateKey().length < engine.getPrivateKeySize())
        {
            key = new CMCEPrivateKeyParameters(engine.decompress_private_key(privateParams.getPrivateKey()), privateParams.getParameters());
        }
    }
    
    public byte[] extractSecret(byte[] encapsulation)
    {
        byte[] session_key = new byte[32];
        engine.kem_dec(session_key, encapsulation, ((CMCEPrivateKeyParameters)key).getPrivateKey());
        return session_key;
    }
}
