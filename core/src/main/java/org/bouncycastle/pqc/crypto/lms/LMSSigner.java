package org.bouncycastle.pqc.crypto.lms;

import java.io.IOException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Exceptions;

public class LMSSigner
    implements MessageSigner
{
    private LMSPrivateKeyParameters privKey;
    private LMSPublicKeyParameters pubKey;

    public void init(boolean forSigning, CipherParameters param)
    {
         if (forSigning)
         {
             if (param instanceof HSSPrivateKeyParameters)
             {
                 HSSPrivateKeyParameters hssPriv = (HSSPrivateKeyParameters)param;
                 if (hssPriv.getL() == 1)
                 {
                     privKey = hssPriv.getRootKey();
                 }
                 else
                 {
                     throw new IllegalArgumentException("only a single level HSS key can be used with LMS");
                 }
             }
             else
             {
                 privKey = (LMSPrivateKeyParameters)param;
             }
         }
         else
         {
             if (param instanceof HSSPublicKeyParameters)
             {
                 HSSPublicKeyParameters hssPub = (HSSPublicKeyParameters)param;
                 if (hssPub.getL() == 1)
                 {
                     pubKey = hssPub.getLMSPublicKey();
                 }
                 else
                 {
                     throw new IllegalArgumentException("only a single level HSS key can be used with LMS");
                 }
             }
             else
             {
                 pubKey = (LMSPublicKeyParameters)param;
             }
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
            throw Exceptions.illegalStateException("unable to encode signature", e);
        }
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        // A malformed/truncated signature must not throw out of verify: the decode
        // can fail with IOException (truncation) or a RuntimeException (out-of-range
        // type fields surface as NullPointerException / NegativeArraySizeException).
        try
        {
            return LMS.verifySignature(pubKey, LMSSignature.getInstance(signature), message);
        }
        catch (IOException e)
        {
            return false;
        }
        catch (RuntimeException e)
        {
            return false;
        }
    }
}
