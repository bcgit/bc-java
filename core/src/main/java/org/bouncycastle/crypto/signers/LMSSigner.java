package org.bouncycastle.crypto.signers;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.HSSPublicKeyParameters;
import org.bouncycastle.crypto.params.LMSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMSPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.lms.LMSContext;
import org.bouncycastle.util.Arrays;

public class LMSSigner
    implements Signer
{
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private LMSContextBasedSigner privKey;
    private boolean hssWrapped;
    private LMSContextBasedVerifier pubKey;

    /**
     * Initialise for signing or verification. A {@link ParametersWithRandom} wrapper is accepted
     * and unwrapped, so a caller that supplies a random - as the operator builders do whenever
     * setSecureRandom() has been called - is not refused; the random itself is not used. The
     * message randomiser C is derived from the key's seed and the one-time index (RFC 8554
     * sec. 4.2, following the reference implementation), so it is deterministic and cannot repeat
     * while q does not.
     *
     * @param forSigning true for signing, false for verification.
     * @param param the key, optionally wrapped in {@link ParametersWithRandom}.
     */
    public void init(boolean forSigning, CipherParameters param)
    {
         // clear both first: a re-init only assigned the key for the mode being set, so a signer
         // initialised for verification kept the private key from an earlier signing init and would
         // still sign with it - and vice versa. Clearing up front also means an init that fails the
         // check below leaves the signer unusable rather than holding the previous key.
         this.privKey = null;
         this.pubKey = null;
         this.hssWrapped = false;

         if (param instanceof ParametersWithRandom)
         {
             param = ((ParametersWithRandom)param).getParameters();
         }

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

         reset();
    }

    /**
     * Sign the passed in message. This is the one-shot form; it must not be mixed with the
     * buffered form, so a call made with data already absorbed through {@link #update(byte)} is
     * refused rather than silently discarding it - call {@link #reset()} first, or use
     * {@link #generateSignature()} to sign what was buffered.
     *
     * @param message the message to be signed.
     * @return the signature.
     * @throws IllegalStateException if a buffered message is present, or the signer is not
     * initialised for signing.
     */
    public byte[] generateSignature(byte[] message)
    {
        if (buffer.size() != 0)
        {
            throw new IllegalStateException("buffered message present: call reset() or use generateSignature()");
        }

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

    /**
     * Verify the passed in signature against the passed in message. This is the one-shot form; it
     * must not be mixed with the buffered form, so a call made with data already absorbed through
     * {@link #update(byte)} is refused rather than silently discarding it - call
     * {@link #reset()} first, or use {@link #verifySignature(byte[])} to verify what was
     * buffered.
     *
     * @param message the message the signature is claimed to be over.
     * @param signature the candidate signature.
     * @return true if the signature verifies, false otherwise.
     * @throws IllegalStateException if a buffered message is present, or the signer is not
     * initialised for verification.
     */
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        if (buffer.size() != 0)
        {
            throw new IllegalStateException("buffered message present: call reset() or use verifySignature(byte[])");
        }

        // checked before the catch-all below so a missing init is reported rather than
        // being folded into "signature did not verify"
        if (pubKey == null)
        {
            throw new IllegalStateException("LMSSigner not initialised for verification");
        }

        // a malformed signature must not throw out of verify; scoped to the decode alone, since
        // past it the engine reports an inconsistent signature by returning false
        LMSContext context;
        try
        {
            context = pubKey.generateLMSContext(signature);
        }
        catch (RuntimeException e)
        {
            return false;
        }

        context.update(message, 0, message.length);

        return pubKey.verify(context);
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
