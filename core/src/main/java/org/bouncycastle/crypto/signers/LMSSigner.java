package org.bouncycastle.crypto.signers;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.HSSPublicKeyParameters;
import org.bouncycastle.crypto.params.LMSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMSPublicKeyParameters;
import org.bouncycastle.crypto.signers.lms.LMSContext;
import org.bouncycastle.util.Arrays;

public class LMSSigner
    implements Signer
{
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private LMSContextBasedSigner privKey;
    private boolean hssWrapped;
    private LMSContextBasedVerifier pubKey;

    public void init(boolean forSigning, CipherParameters param)
    {
         // clear both first: a re-init only assigned the key for the mode being set, so a signer
         // initialised for verification kept the private key from an earlier signing init and would
         // still sign with it - and vice versa. Clearing up front also means an init that fails the
         // check below leaves the signer unusable rather than holding the previous key.
         this.privKey = null;
         this.pubKey = null;
         this.hssWrapped = false;

         if (forSigning)
         {
             if (param instanceof HSSPrivateKeyParameters)
             {
                 HSSPrivateKeyParameters hssPriv = (HSSPrivateKeyParameters)param;
                 if (hssPriv.getL() == 1)
                 {
                     //
                     // Sign through the HSS key so its index advances with the root tree's, and
                     // strip the u32str(Nspk = 0) prefix that is all a single-level HSS signature
                     // adds to the LMS one (RFC 8554 sec. 6.1).
                     //
                     privKey = hssPriv;
                     hssWrapped = true;
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

        LMSContext context = privKey.generateLMSContext();

        context.update(message, 0, message.length);

        byte[] signature = privKey.generateSignature(context);

        if (hssWrapped)
        {
            return Arrays.copyOfRange(signature, 4, signature.length);
        }

        return signature;
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
        // can fail on truncation (surfacing as IllegalStateException) or with another
        // RuntimeException (out-of-range type fields surface as NullPointerException /
        // NegativeArraySizeException).
        try
        {
            LMSContext context = pubKey.generateLMSContext(signature);

            context.update(message, 0, message.length);

            return pubKey.verify(context);
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
