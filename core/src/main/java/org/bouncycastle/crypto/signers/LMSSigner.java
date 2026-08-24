package org.bouncycastle.crypto.signers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.HSSPublicKeyParameters;
import org.bouncycastle.crypto.params.LMSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMSPublicKeyParameters;
import org.bouncycastle.crypto.signers.lms.HSS;
import org.bouncycastle.crypto.signers.lms.LMS;
import org.bouncycastle.crypto.signers.lms.LMSSignature;
import org.bouncycastle.util.Exceptions;

public class LMSSigner
    implements Signer
{
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private LMSPrivateKeyParameters privKey;
    private LMSPublicKeyParameters pubKey;

    public void init(boolean forSigning, CipherParameters param)
    {
         // clear both first: a re-init only assigned the key for the mode being set, so a signer
         // initialised for verification kept the private key from an earlier signing init and would
         // still sign with it - and vice versa. Clearing up front also means an init that fails the
         // check below leaves the signer unusable rather than holding the previous key.
         this.privKey = null;
         this.pubKey = null;

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
        if (privKey == null)
        {
            throw new IllegalStateException("LMSSigner not initialised for signature generation");
        }

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
        // checked before the catch-all below so a missing init is reported rather than
        // being folded into "signature did not verify"
        if (pubKey == null)
        {
            throw new IllegalStateException("LMSSigner not initialised for verification");
        }

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

    /**
     * Absorb a byte of the message to be signed or verified. The buffered message is consumed by
     * {@link #generateSignature()} / {@link #verifySignature(byte[])}, which reset the buffer.
     */
    public void update(byte b)
    {
        buffer.write(b);
    }

    public void update(byte[] in, int off, int len)
    {
        buffer.write(in, off, len);
    }

    public byte[] generateSignature()
    {
        byte[] message = buffer.toByteArray();

        reset();

        return generateSignature(message);
    }

    public boolean verifySignature(byte[] signature)
    {
        byte[] message = buffer.toByteArray();

        reset();

        return verifySignature(message, signature);
    }

    public void reset()
    {
        buffer.reset();
    }
}
