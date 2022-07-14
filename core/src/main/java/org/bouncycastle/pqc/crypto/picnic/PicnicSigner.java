package org.bouncycastle.pqc.crypto.picnic;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Pack;

public class PicnicSigner
    implements MessageSigner
{
    private PicnicPrivateKeyParameters privKey;
    private PicnicPublicKeyParameters pubKey;

    public PicnicSigner()
    {
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

        byte[] signature = new byte[engine.getTrueSignatureSize()];
        System.arraycopy(sig, message.length + 4, signature, 0, engine.getTrueSignatureSize());
        return signature;
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        PicnicEngine engine = pubKey.getParameters().getEngine();
        byte[] verify_message = new byte[message.length];
        byte[] attached_signature = Arrays.concatenate(Pack.intToLittleEndian(signature.length), message, signature);

        boolean verify = engine.crypto_sign_open(verify_message, attached_signature, pubKey.getEncoded());
        if(!Arrays.areEqual(message, verify_message))
        {
            return false;
        }
        return verify;
    }
}
