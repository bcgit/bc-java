package org.bouncycastle.pqc.crypto.picnic;

import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.MessageSigner;

public class PicnicSigner
    implements MessageSigner
{
    private PicnicPrivateKeyParameters privKey;
    private PicnicPublicKeyParameters pubKey;

    private SecureRandom random;

    public PicnicSigner(SecureRandom random)
    {
        this.random = random;
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        if(forSigning)
        {
            privKey = (PicnicPrivateKeyParameters) param;
        }
        else
        {
            pubKey = (PicnicPublicKeyParameters) param;
        }

    }

    public byte[] generateSignature(byte[] message)
    {
        PicnicEngine engine = privKey.getParameters().getEngine();
        byte[] sig = new byte[engine.getSignatureSize(message.length)];
        engine.crypto_sign(sig, message , privKey.getEncoded());

        return Arrays.copyOfRange(sig, 0 , message.length  + engine.getTrueSignatureSize());
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        PicnicEngine engine = pubKey.getParameters().getEngine();
        byte[] verify_message = new byte[message.length];
        boolean verify = engine.crypto_sign_open(verify_message, signature, pubKey.getEncoded());
        if(!Arrays.equals(message, verify_message))
        {
            return false;
        }
        return verify;
    }
}
