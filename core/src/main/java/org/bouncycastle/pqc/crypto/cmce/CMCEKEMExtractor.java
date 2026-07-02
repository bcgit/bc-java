package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;

/**
 * @deprecated the standardised Classic McEliece KEM (ISO/IEC 18033-2:2006/Amd 2:2026) is now provided under org.bouncycastle.crypto and org.bouncycastle.jcajce (see org.bouncycastle.crypto.params.CMCEParameters and org.bouncycastle.jcajce.spec.CMCEParameterSpec). This is the legacy NIST round 3 (non-pc, incl. mceliece348864) implementation, retained for backwards compatibility.
 */
@Deprecated
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
        CMCEPrivateKeyParameters privateParams = (CMCEPrivateKeyParameters)key;
        if(privateParams.getPrivateKey().length < engine.getPrivateKeySize())
        {
            key = new CMCEPrivateKeyParameters(privateParams.getParameters(), engine.decompress_private_key(privateParams.getPrivateKey()));
        }
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        return extractSecret(encapsulation, engine.getDefaultSessionKeySize());
    }

    public byte[] extractSecret(byte[] encapsulation, int sessionKeySizeInBits)
    {
        if (encapsulation.length != getEncapsulationLength())
        {
            throw new IllegalArgumentException("encapsulation wrong length");
        }
        byte[] session_key = new byte[sessionKeySizeInBits / 8];
        engine.kem_dec(session_key, encapsulation, ((CMCEPrivateKeyParameters)key).getPrivateKey());
        return session_key;
    }

    public int getEncapsulationLength()
    {
        return engine.getCipherTextSize();
    }
}
