package org.bouncycastle.crypto.signers;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.HSSPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.lms.LMSContext;

public class HSSSigner
    implements Signer
{
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private HSSPrivateKeyParameters privKey;
    private HSSPublicKeyParameters pubKey;

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
         // still sign with it - and vice versa.
         this.privKey = null;
         this.pubKey = null;

         if (param instanceof ParametersWithRandom)
         {
             param = ((ParametersWithRandom)param).getParameters();
         }

         if (forSigning)
         {
             this.privKey = (HSSPrivateKeyParameters)param;
         }
         else
         {
             this.pubKey = (HSSPublicKeyParameters)param;
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
            throw new IllegalStateException("HSSSigner not initialised for signature generation");
        }

        LMSContext context = privKey.generateLMSContext();

        context.update(message, 0, message.length);

        return privKey.generateSignature(context);
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
            throw new IllegalStateException("HSSSigner not initialised for verification");
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
