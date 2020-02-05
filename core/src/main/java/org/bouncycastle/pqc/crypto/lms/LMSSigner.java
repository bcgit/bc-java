package org.bouncycastle.pqc.crypto.lms;

import java.io.IOException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.MessageSigner;

public class LMSSigner
    implements MessageSigner
{
    private LMSPrivateKeyParameters privKey;
    private LMSPublicKeyParameters pubKey;

    public void init(boolean forSigning, CipherParameters param)
    {
         if (forSigning)
         {
             privKey = (LMSPrivateKeyParameters)param;
         }
         else
         {
             pubKey = (LMSPublicKeyParameters)param;
         }
    }

    public byte[] generateSignature(byte[] message)
    {
        try
        {
            return LMS.generateSign(privKey, message).getEncoded();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to encode signature: " + e.getMessage());
        }
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        try
        {
            return LMS.verifySignature(pubKey, LMSSignature.getInstance(signature), message);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to decode signature: " + e.getMessage());
        }
    }
}
