package org.bouncycastle.crypto.signers.lms;

import java.io.IOException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.HSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.HSSPublicKeyParameters;
import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMSPublicKeyParameters;
import org.bouncycastle.crypto.params.LMSigParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

/**
 * The LMS and HSS operations of RFC 8554 that the key parameter classes in
 * {@link org.bouncycastle.crypto.params} and the key pair generators in
 * {@link org.bouncycastle.crypto.generators} call into. This is the whole public surface of the
 * engine: the value classes for one-time keys and signatures, the seed derivation and the
 * encoding helpers are package-private and no compatibility is promised for them. Applications
 * sign and verify through {@link org.bouncycastle.crypto.signers.LMSSigner} /
 * {@link org.bouncycastle.crypto.signers.HSSSigner}, or the
 * {@link org.bouncycastle.crypto.signers.LMSContextBasedSigner} /
 * {@link org.bouncycastle.crypto.signers.LMSContextBasedVerifier} the key classes implement.
 */
public final class LMSEngine
{
    private static final short D_LEAF = (short)0x8282;
    private static final short D_INTR = (short)0x8383;

    private LMSEngine()
    {
    }

    //
    // Merkle tree construction (RFC 8554 sec. 5.3, Algorithm 5 / 6).
    //

    /**
     * The digest an LMS tree over the given parameters is built with.
     */
    public static Digest createDigest(LMSigParameters sigParameters)
    {
        return DigestUtil.getDigest(sigParameters);
    }

    /**
     * Leaf node r of the tree: H(I || u32str(r) || u16str(D_LEAF) || OTS_PUB_HASH[q]), where the
     * one-time public key for leaf q is derived from the master secret.
     *
     * @param H the tree digest, from {@link #createDigest(LMSigParameters)}; reset on return.
     */
    public static byte[] computeLeaf(Digest H, LMOtsParameters otsParameters, byte[] I, int r, int q, byte[] masterSecret)
    {
        byte[] K = LM_OTS.lms_ots_generatePublicKey(otsParameters, I, q, masterSecret);

        LmsUtils.byteArray(I, H);
        LmsUtils.u32str(r, H);
        LmsUtils.u16str(D_LEAF, H);
        LmsUtils.byteArray(K, H);

        byte[] T = new byte[H.getDigestSize()];
        H.doFinal(T, 0);

        return T;
    }

    /**
     * Interior node r of the tree: H(I || u32str(r) || u16str(D_INTR) || T[2r] || T[2r+1]).
     *
     * @param H the tree digest, from {@link #createDigest(LMSigParameters)}; reset on return.
     */
    public static byte[] computeNode(Digest H, byte[] I, int r, byte[] left, byte[] right)
    {
        LmsUtils.byteArray(I, H);
        LmsUtils.u32str(r, H);
        LmsUtils.u16str(D_INTR, H);
        LmsUtils.byteArray(left, H);
        LmsUtils.byteArray(right, H);

        byte[] T = new byte[H.getDigestSize()];
        H.doFinal(T, 0);

        return T;
    }

    //
    // Signing.
    //

    /**
     * The context a message is absorbed into before signing with one-time key q of an LMS tree
     * (RFC 8554 sec. 5.4.1): the randomiser C is derived and the I || q || D_MESG || C prefix is
     * already absorbed. Consumed by {@link #generateSign(LMSContext)}.
     */
    public static LMSContext generateSignContext(LMSigParameters sigParameters, LMOtsParameters otsParameters,
                                                 byte[] I, int q, byte[] masterSecret, byte[][] path)
    {
        return new LMOtsPrivateKey(otsParameters, I, q, masterSecret).getSignatureContext(sigParameters, path);
    }

    /**
     * Attach the signed public key chain of an HSS signature (RFC 8554 sec. 6.1) to the context
     * for its leaf tree, so that {@link #generateHSSSignature(int, LMSContext)} can emit it.
     *
     * @param signatures the L - 1 chaining signatures, signatures[i] made by tree i over the
     *                   public key of tree i + 1.
     * @param publicKeys the public keys of trees 1 .. L - 1.
     */
    public static LMSContext withSignedPublicKeys(LMSContext context, LMSSignature[] signatures, LMSPublicKeyParameters[] publicKeys)
    {
        LMSSignedPubKey[] signedPubKeys = new LMSSignedPubKey[signatures.length];
        for (int i = 0; i != signedPubKeys.length; i++)
        {
            signedPubKeys[i] = new LMSSignedPubKey(signatures[i], publicKeys[i]);
        }

        return context.withSignedPublicKeys(signedPubKeys);
    }

    /**
     * Complete an LMS signature over the message absorbed into a context from
     * {@link #generateSignContext}.
     */
    public static LMSSignature generateSign(LMSContext context)
    {
        // Step 1.
        LMOtsSignature ots_signature = LM_OTS.lm_ots_generate_signature(context.getPrivateKey(), context.getQ(), context.getC());

        return new LMSSignature(context.getPrivateKey().getQ(), ots_signature, context.getSigParams(), context.getPath());
    }

    /**
     * Complete and encode an HSS signature over the message absorbed into a context from
     * {@link #generateSignContext} that has had its chain attached with {@link #withSignedPublicKeys}.
     *
     * @param L the number of levels in the HSS key.
     */
    public static byte[] generateHSSSignature(int L, LMSContext context)
    {
        try
        {
            return new HSSSignature(L - 1, context.getSignedPubKeys(), generateSign(context)).getEncoded();
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("unable to encode signature: " + e.getMessage(), e);
        }
    }

    //
    // Verification.
    //

    /**
     * The context a message is absorbed into before verifying an encoded LMS signature against a
     * public key. Consumed by {@link #verifySignature(LMSPublicKeyParameters, LMSContext)}.
     *
     * @throws IllegalStateException if the signature does not decode.
     */
    public static LMSContext generateVerifyContext(LMSPublicKeyParameters publicKey, byte[] signature)
    {
        try
        {
            return generateVerifyContext(publicKey, LMSSignature.getInstance(signature));
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("cannot parse signature", e);
        }
    }

    /**
     * The typecode and leaf-number checks RFC 8554 sec. 5.4.2 requires before a signature is
     * processed: step 2g refuses a signature whose LMS typecode is not the one from the public key,
     * and step 2i refuses a leaf number q outside the tree. Without the first, the path computation
     * below took its height and tree digest from the parameter set the signature named rather than
     * the key's, so a signature claiming h25 drove a 25-level computation against an h5 key; without
     * the second, an out-of-range q flowed into the node arithmetic and was left to be caught by the
     * candidate-root comparison. Neither was a forgery under a secure hash - the domain separation
     * and the final comparison saw to that - but both are work the specification says to refuse up
     * front.
     */
    static LMSContext generateVerifyContext(LMSPublicKeyParameters publicKey, LMSSignature S)
    {
        LMSigParameters sigParameters = publicKey.getSigParameters();
        if (S.getParameter().getType() != sigParameters.getType())
        {
            throw new IllegalArgumentException("lms type from lms signature does not match lms type" +
                " from public key");
        }

        int q = S.getQ();
        if (q < 0 || q >= (1 << sigParameters.getH()))
        {
            throw new IllegalArgumentException("lms leaf number q from lms signature is outside the" +
                " public key's tree");
        }

        int ots_typecode = publicKey.getOtsParameters().getType();
        if (S.getOtsSignature().getType().getType() != ots_typecode)
        {
            throw new IllegalArgumentException("ots type from lsm signature does not match ots" +
                " signature type from embedded ots signature");
        }

        return new LMOtsPublicKey(LMOtsParameters.getParametersForType(ots_typecode), publicKey.getI(), S.getQ(), null).createOtsContext(S);
    }

    /**
     * Verify the LMS signature a context from {@link #generateVerifyContext} carries over the
     * message absorbed into it (RFC 8554 sec. 5.4.2, Algorithm 6).
     */
    public static boolean verifySignature(LMSPublicKeyParameters publicKey, LMSContext context)
    {
        LMSSignature S = (LMSSignature)context.getSignature();
        LMSigParameters lmsParameter = S.getParameter();
        int h = lmsParameter.getH();
        byte[][] path = S.getY();
        byte[] Kc = LM_OTS.lm_ots_validate_signature_calculate(context);
        // Step 4
        // node_num = 2^h + q
        int node_num = (1 << h) + S.getQ();

        // tmp = H(I || u32str(node_num) || u16str(D_LEAF) || Kc)
        byte[] I = publicKey.getI();
        Digest H = DigestUtil.getDigest(lmsParameter);
        byte[] tmp = new byte[H.getDigestSize()];

        H.update(I, 0, I.length);
        LmsUtils.u32str(node_num, H);
        LmsUtils.u16str(D_LEAF, H);
        H.update(Kc, 0, Kc.length);
        H.doFinal(tmp, 0);

        int i = 0;

        while (node_num > 1)
        {
            if ((node_num & 1) == 1)
            {
                // is odd
                H.update(I, 0, I.length);
                LmsUtils.u32str(node_num / 2, H);
                LmsUtils.u16str(D_INTR, H);
                H.update(path[i], 0, path[i].length);
                H.update(tmp, 0, tmp.length);
                H.doFinal(tmp, 0);
            }
            else
            {
                H.update(I, 0, I.length);
                LmsUtils.u32str(node_num / 2, H);
                LmsUtils.u16str(D_INTR, H);
                H.update(tmp, 0, tmp.length);
                H.update(path[i], 0, path[i].length);
                H.doFinal(tmp, 0);
            }
            node_num = node_num / 2;
            i++;
            // these two can get out of sync with an invalid signature, we'll
            // try and fail gracefully
            if (i == path.length && node_num > 1)
            {
                return false;
            }
        }
        byte[] Tc = tmp;
        return Arrays.constantTimeAreEqual(publicKey.getT1(), Tc);
    }

    static boolean verifySignature(LMSPublicKeyParameters publicKey, LMSSignature S, byte[] message)
    {
        LMSContext context = generateVerifyContext(publicKey, S);

        LmsUtils.byteArray(message, context);

        return verifySignature(publicKey, context);
    }

    /**
     * The context a message is absorbed into before verifying an encoded HSS signature against a
     * public key: the signature's signed public key chain is decoded and attached, and the context
     * is for its leaf tree. Consumed by {@link #verifyHSSSignature(HSSPublicKeyParameters, LMSContext)}.
     *
     * @throws IllegalStateException if the signature does not decode or its level count does not
     *                               match the key's.
     */
    public static LMSContext generateHSSVerifyContext(HSSPublicKeyParameters publicKey, byte[] signature)
    {
        HSSSignature hssSignature;
        try
        {
            hssSignature = HSSSignature.getInstance(signature, publicKey.getL());
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("cannot parse signature", e);
        }

        LMSSignedPubKey[] signedPubKeys = hssSignature.getSignedPubKey();
        LMSPublicKeyParameters key;
        if (signedPubKeys.length != 0)
        {
            key = signedPubKeys[signedPubKeys.length - 1].getPublicKey();
        }
        else
        {
            key = publicKey.getLMSPublicKey();
        }

        return generateVerifyContext(key, hssSignature.getSignature()).withSignedPublicKeys(signedPubKeys);
    }

    /**
     * Verify the HSS signature a context from {@link #generateHSSVerifyContext} carries over the
     * message absorbed into it (RFC 8554 sec. 6.3): each chaining signature over the next tree's
     * public key, then the leaf tree's signature over the message.
     */
    public static boolean verifyHSSSignature(HSSPublicKeyParameters publicKey, LMSContext context)
    {
        boolean passed = true;

        LMSSignedPubKey[] sigKeys = context.getSignedPubKeys();

        if (sigKeys.length != publicKey.getL() - 1)
        {
            return false;
        }

        LMSPublicKeyParameters key = publicKey.getLMSPublicKey();

        for (int i = 0; i < sigKeys.length; i++)
        {
            LMSSignature sig = sigKeys[i].getSignature();
            byte[] msg = encodePublicKey(sigKeys[i].getPublicKey());
            passed &= verifySignature(key, sig, msg);
            key = sigKeys[i].getPublicKey();
        }

        return passed & verifySignature(key, context);
    }

    private static byte[] encodePublicKey(LMSPublicKeyParameters publicKey)
    {
        try
        {
            return publicKey.getEncoded();
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("unable to encode public key", e);
        }
    }

    //
    // HSS key management (RFC 8554 sec. 6.1).
    //

    /**
     * Generate an HSS private key: a root LMS key drawn from the parameters' random source, with
     * the lower trees derived from it when the key is first positioned at index 0.
     */
    public static HSSPrivateKeyParameters generateHSSKeyPair(HSSKeyGenerationParameters parameters)
    {
        //
        // LmsPrivateKey can derive and hold the public key so we just use an array of those.
        //
        LMSPrivateKeyParameters[] keys = new LMSPrivateKeyParameters[parameters.getDepth()];
        LMSSignature[] sig = new LMSSignature[parameters.getDepth() - 1];

        byte[] rootSeed = new byte[parameters.getLmsParameters()[0].getLMSigParam().getM()];
        parameters.getRandom().nextBytes(rootSeed);

        byte[] I = new byte[16];
        parameters.getRandom().nextBytes(I);

        //
        // Set the HSS key up with a valid root LMSPrivateKeyParameters and placeholders for the remaining LMS keys.
        // The placeholders pass enough information to allow the HSSPrivateKeyParameters to be properly reset to an
        // index of zero. Rather than repeat the same reset-to-index logic in this static method.
        //

        long hssKeyMaxIndex = 1;
        for (int t = 0; t < keys.length; t++)
        {
            if (t == 0)
            {
                keys[t] = new LMSPrivateKeyParameters(
                    parameters.getLmsParameters()[t].getLMSigParam(),
                    parameters.getLmsParameters()[t].getLMOTSParam(),
                    0,
                    I,
                    1 << parameters.getLmsParameters()[t].getLMSigParam().getH(),
                    rootSeed);
            }
            else
            {
                keys[t] = new PlaceholderLMSPrivateKey(
                    parameters.getLmsParameters()[t].getLMSigParam(),
                    parameters.getLmsParameters()[t].getLMOTSParam(),
                    1 << parameters.getLmsParameters()[t].getLMSigParam().getH());
            }
            hssKeyMaxIndex *= 1 << parameters.getLmsParameters()[t].getLMSigParam().getH();
        }

        // if this has happened we're trying to generate a really large key
        // we'll use MAX_VALUE so that it's at least usable until someone upgrades the structure.
        if (hssKeyMaxIndex == 0)
        {
            hssKeyMaxIndex = Long.MAX_VALUE;
        }

        return new HSSPrivateKeyParameters(
            parameters.getDepth(),
            java.util.Arrays.asList(keys),
            java.util.Arrays.asList(sig),
            0, hssKeyMaxIndex);
    }

    /**
     * Derive the identifier and master seed of the tree below one-time key q of an LMS tree
     * (the child of leaf q in an HSS hierarchy).
     *
     * @return { I of the child tree (16 bytes), master seed of the child tree (n bytes) }.
     */
    public static byte[][] deriveChildKey(LMOtsParameters otsParameters, byte[] I, byte[] masterSecret, int q)
    {
        int n = otsParameters.getN();

        SeedDerive derive = new SeedDerive(I, masterSecret, DigestUtil.getDigest(otsParameters));
        derive.setQ(q);
        derive.setJ(~1);

        byte[] childSeed = new byte[n];
        derive.deriveSeed(childSeed, true);
        byte[] postImage = new byte[n];
        derive.deriveSeed(postImage, false);
        byte[] childI = new byte[16];
        System.arraycopy(postImage, 0, childI, 0, childI.length);

        return new byte[][]{ childI, childSeed };
    }

    private static class PlaceholderLMSPrivateKey
        extends LMSPrivateKeyParameters
    {
        PlaceholderLMSPrivateKey(LMSigParameters lmsParameter, LMOtsParameters otsParameters, int maxQ)
        {
            super(lmsParameter, otsParameters, maxQ);
        }

        public LMSContext generateLMSContext()
        {
            throw new RuntimeException("placeholder only");
        }

        public LMSPublicKeyParameters getPublicKey()
        {
            throw new RuntimeException("placeholder only");
        }
    }
}
