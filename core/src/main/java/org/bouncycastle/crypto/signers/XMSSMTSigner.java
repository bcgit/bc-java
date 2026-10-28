package org.bouncycastle.crypto.signers;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSMTPublicKeyParameters;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;

/**
 * XMSS^MT Signer class.
 */
public class XMSSMTSigner
    implements Signer
{
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private XMSSMTPrivateKeyParameters privateKey;
    private XMSSMTPublicKeyParameters publicKey;

    private boolean hasGenerated;
    private boolean initSign;
    // what a collection that followed no signature handed back, so a second one can hand back the
    // same object rather than shard the single usage this signer kept for itself. Null once a
    // signature has spent that usage, and on every init().
    private XMSSMTPrivateKeyParameters collected;

    // whether that collection happened at all, which outlives the field above: that one is
    // cleared when the signature spends the usage this signer kept, and this is what still says
    // the rest of the key is already in the caller's hands. Cleared only by init().
    private boolean collectedRemainder;

    /**
     * Initialise for signing or verification. A {@link ParametersWithRandom} wrapper is accepted
     * and unwrapped before either branch is entered, the way LMSSigner.init accepts it, so a
     * caller that wraps its key once and drives both sides is not refused by the verification
     * one; the random the wrapper carries is not used. The randomizer r is derived from the key
     * itself - r = PRF(SK_PRF, toByte(idx, 32)), RFC 8391 sec. 4.2.7 - so a SecureRandom supplied
     * here has nothing to drive and is discarded, the way SPHINCS256Signer discards it. On the
     * signing side accepting the wrapper is what BC itself needs:
     * XMSSMTSignatureSpi.engineInitSign(PrivateKey, SecureRandom) wraps the key whenever a random
     * is supplied, so initSign(key, random) used to fail on the cast.
     *
     * @param forSigning true for signing, false for verification.
     * @param param the key, optionally wrapped in {@link ParametersWithRandom}.
     */
    public void init(boolean forSigning, CipherParameters param)
    {
        if (param instanceof ParametersWithRandom)
        {
            param = ((ParametersWithRandom)param).getParameters();
        }

        // under the same monitor generateSignature() and getUpdatedPrivateKey() take: this is the
        // other place the private key field is assigned, and an init landing part way through a
        // signature would otherwise leave the two disagreeing about which key is being spent
        synchronized (this)
        {
            if (forSigning)
            {
                initSign = true;
                hasGenerated = false;
                collected = null;
                collectedRemainder = false;
                privateKey = (XMSSMTPrivateKeyParameters)param;

                // the public key from a previous verification init must not stay behind, or this
                // signer still verifies against it. The private key is deliberately NOT cleared on
                // a verification init: sign then verify then collect the advanced state is a
                // legitimate sequence, and clearing would drop state the caller must persist.
                publicKey = null;
            }
            else
            {
                initSign = false;
                publicKey = (XMSSMTPublicKeyParameters)param;
            }

            XMSSMTParameters params = forSigning ? privateKey.getParameters() : publicKey.getParameters();
            CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("XMSSMT",
                params.getClassicalSecurityStrength(), param, forSigning));

            // a message absorbed before this call belongs to the operation that has just ended:
            // carrying it into the new one would sign or verify bytes the caller never presented
            // for it, and on the signing side would spend a one-time key doing so. Ed25519Signer,
            // Ed448Signer and DSADigestSigner all reset here for the same reason.
            reset();
        }
    }

    public byte[] generateSignature()
    {
        // on this signer's own monitor rather than on the key the field happens to hold: the field
        // is reassigned by getUpdatedPrivateKey() and by init(), so a lock taken on the object read
        // out of it excludes nothing from a call that has already read a different one. Two calls
        // would then be inside the engine at once holding keys that sit on the same position, and
        // RFC 8391 sec. 1.1 makes that one one-time key signing twice. The key's own monitor is
        // still taken below, where it is what excludes a second signer initialised on the same key.
        synchronized (this)
        {
            byte[] message = buffer.toByteArray();

            // the buffered message is consumed whether or not a signature is produced: a call that
            // fails one of the checks below must not leave bytes behind for the next one to sign
            reset();

            XMSSMTPrivateKeyParameters privKey = privateKey;

            if (initSign)
            {
                if (privKey == null)
                {
                    throw new IllegalStateException("signing key no longer usable");
                }
            }
            else
            {
                throw new IllegalStateException("signer not initialized for signature generation");
            }

            synchronized (privKey)
            {
                if (privKey.getUsagesRemaining() <= 0)
                {
                    throw new ExhaustedPrivateKeyException("no usages of private key remaining");
                }
                if (!XMSSEngine.hasTraversalState(privKey))
                {
                    throw new IllegalStateException("not initialized");
                }

                // set from whether the key was rolled, because that is what getUpdatedPrivateKey()
                // has to know: a rolled key is handed straight back, an unrolled one is advanced
                // first. Neither side of the call answers it. The engine refuses a signature before
                // it touches the key - its own "has already signed" check sits ahead of the try
                // whose finally rolls - so set ahead of the call this reports a key spent by a
                // signature that never happened, and the collection that follows empties this
                // signer for nothing; set after it, a signature that failed part way through leaves
                // a rolled key looking unrolled, and the collection advances it a second time. The
                // key answers instead: rollKey() moves the index by exactly one, and this thread
                // holds the key's monitor across the call, so an index that has moved is one this
                // signer moved. Once true it stays true until init() clears it - a later refusal
                // cannot unsay an earlier signature.
                long indexBefore = privKey.getIndex();

                try
                {
                    return XMSSEngine.generateMTSignature(privKey, message);
                }
                finally
                {
                    if (privKey.getIndex() != indexBefore)
                    {
                        hasGenerated = true;
                        collected = null;
                    }
                }
            }
        }
    }

    /**
     * Verify the buffered message against the passed in signature.
     * <p>
     * No monitor is taken here, the way the legacy signer and {@code LMSSigner} take none. This
     * reads the public key and the mode flag, spends no one-time key and advances no traversal
     * state, so there is nothing for a lock to serialize; and it could not serialize the message
     * in any case, since {@link #update(byte)} and {@link #reset()} write the buffer without one,
     * so a monitor held over the read alone excludes nothing a caller sharing one signer across
     * threads is doing. What the signing side takes this monitor for is the private key field,
     * which {@link #getUpdatedPrivateKey()} reassigns; nothing reassigns the public key but
     * {@link #init(boolean, CipherParameters)}, and re-initialising a signer under a running
     * operation is the caller error it is in every other signer here.
     * </p>
     */
    public boolean verifySignature(byte[] signature)
    {
        byte[] message = buffer.toByteArray();

        // consumed whatever the outcome, so a failed verification cannot poison the next one
        reset();

        // covers both a signer initialised for signing and one never initialised at all, and
        // comes ahead of the delegation below so that it beats the engine's own argument
        // checks: not being initialised is the caller's first problem. This replaces the
        // NullPointerException the absent public key used to raise.
        if (initSign || publicKey == null)
        {
            throw new IllegalStateException("signer not initialized for verification");
        }

        return XMSSEngine.verifyMTSignature(publicKey, message, signature);
    }

    /**
     * Return the number of signatures the key this signer holds can still produce. A signer that
     * has never been initialised for signing, or one whose key has already been handed back by
     * {@link #getUpdatedPrivateKey()}, holds no key and so reports zero - reading the absent key
     * would otherwise raise a NullPointerException.
     * <p>
     * Initialising for verification is not one of those cases: {@link #init(boolean,
     * org.bouncycastle.crypto.CipherParameters)} deliberately leaves the private key in place, so
     * that sign then verify then collect stays a legitimate sequence, and a signer that has signed
     * and then been re-initialised to verify goes on reporting that key's count. What this answers
     * is what the key it holds has left, not whether the signer is currently able to sign.
     * </p><p>
     * No monitor is taken, the way the legacy signer takes none and the two key parameter classes
     * LMS was promoted as leave their own getUsagesRemaining() unsynchronized. What this returns
     * is a count and not a reservation: it is out of date the moment any monitor held over it is
     * dropped, because the next signature made on that key - by this signer or by another holding
     * it - moves it. The field read is of a reference and so cannot tear, and the key's own
     * accessor takes the key's monitor for the traversal state the count is derived from.
     * </p>
     */
    public long getUsagesRemaining()
    {
        XMSSMTPrivateKeyParameters privKey = privateKey;

        if (privKey == null)
        {
            return 0;
        }

        return privKey.getUsagesRemaining();
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

    public void reset()
    {
        buffer.reset();
    }

    public AsymmetricKeyParameter getUpdatedPrivateKey()
    {
        // if we've generated a signature return the last private key generated
        // if we've only initialised leave it in place and return the next one instead.
        //
        // on this signer's monitor, as generateSignature() is: this call replaces the field, so one
        // running beside a signature that had already read the old value would leave the key it
        // hands back for storage sitting on the very index that signature is about to spend.
        synchronized (this)
        {
            XMSSMTPrivateKeyParameters privKey = privateKey;

            // nothing to hand back: this signer was never initialised for signing, or a previous
            // call has already taken the key. Reported as an absent key rather than as the
            // NullPointerException synchronizing on the field below would raise.
            if (privKey == null)
            {
                return null;
            }

            synchronized (privKey)
            {
                if (hasGenerated)
                {
                    privateKey = null;

                    // the rest of this key is already with the caller: a collection made before
                    // the signature handed back everything but the one usage the signature has
                    // now spent, so what is left here is a spent shard that adds nothing to what
                    // was stored. Reported as an absent key - which is what the signature SPI
                    // turns back into the "signature object not in a signing state" its own
                    // collection raised for this sequence before a shard was handed back at all.
                    // Handing the shard over instead loses state rather than preserving it: a
                    // caller collecting in a finally beside an explicit collection overwrites the
                    // remainder with a key reporting nothing remaining.
                    if (collectedRemainder)
                    {
                        return null;
                    }
                }
                else if (collected != null)
                {
                    // asked twice with no signature between. The key handed over the first time is
                    // still the whole of what this signer is not keeping, so hand back that same
                    // object: rolling again would shard the single usage kept for signing, leaving
                    // the caller a key reporting nothing remaining while the usages it was given
                    // the first time live only in a return value it has been given no reason to
                    // think it still needs. A caller that stores the latest collection - a retry
                    // after a failed write, a collection in a finally beside an explicit one -
                    // would persist the empty one and lose the rest.
                    return collected;
                }
                else if (privKey.getUsagesRemaining() > 0)
                {
                    privateKey = privKey.getNextKey();
                    collected = privKey;
                    collectedRemainder = true;
                }
                // else: a key with nothing left to spend has no next usage to leave behind, and
                // asking for one reported the shard API's own "usageCount exceeds usages remaining"
                // to a caller that never asked for a shard. Hand the spent key back so it can still
                // be stored - and again on a second call, since nothing was consumed handing it over.

                return privKey;
            }
        }
    }
}
