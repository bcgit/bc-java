package org.bouncycastle.pqc.crypto.lms;

import java.io.IOException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Exceptions;

public class HSSSigner
    implements MessageSigner
{
    private HSSPrivateKeyParameters privKey;
    private HSSPublicKeyParameters pubKey;

    public void init(boolean forSigning, CipherParameters param)
    {
         // clear both first: a re-init only assigned the key for the mode being set, so a signer
         // initialised for verification kept the private key from an earlier signing init and would
         // still sign with it - and vice versa.
         this.privKey = null;
         this.pubKey = null;

         if (forSigning)
         {
             this.privKey = (HSSPrivateKeyParameters)param;
         }
         else
         {
             this.pubKey = (HSSPublicKeyParameters)param;
         }
    }

    public byte[] generateSignature(byte[] message)
    {
        if (privKey == null)
        {
            throw new IllegalStateException("HSSSigner not initialised for signature generation");
        }

        try
        {
            return HSS.generateSignature(privKey, message).getEncoded();
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("unable to encode signature", e);
        }
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        // checked before the catch-all below so a missing init is reported rather than
        // being folded into "signature did not verify"
        if (pubKey == null)
        {
            throw new IllegalStateException("HSSSigner not initialised for verification");
        }

        // A malformed/truncated signature must not throw out of verify: the decode
        // can fail with IOException (truncation) or a RuntimeException (out-of-range
        // type fields surface as NullPointerException / NegativeArraySizeException).
        try
        {
            return HSS.verifySignature(pubKey, HSSSignature.getInstance(signature, pubKey.getL()), message);
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
