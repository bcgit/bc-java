package org.bouncycastle.crypto.signers.xmss;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSMTPublicKeyParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSPublicKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * The XMSS and XMSS^MT (RFC 8391) operations the key parameter classes, the key pair generators and
 * the signers are built on: key pair generation, signature generation and verification, the WOTS+
 * and OID parameter derivations, and the handful of encoding helpers the key classes need.
 * <p>
 * This is the only public class of the package besides the two opaque BDS traversal-state types
 * ({@link BDS} and {@link BDSStateMap}, which an XMSS / XMSS^MT private key carries as a field and
 * so cannot be package-private). Everything else here - WOTS+, the hash addressing scheme, the
 * keyed hash functions, the tree arithmetic and the signature structures - is implementation
 * detail, and no compatibility is promised for it.
 */
public final class XMSSEngine
{
    private XMSSEngine()
    {
    }

    /**
     * The OID of a digest by its algorithm name, for the tree digest of an XMSS parameter set.
     */
    public static ASN1ObjectIdentifier getDigestOID(String name)
    {
        return DigestUtil.getDigestOID(name);
    }

    /**
     * The algorithm name of a tree digest OID.
     */
    public static String getDigestName(ASN1ObjectIdentifier oid)
    {
        return DigestUtil.getDigestName(oid);
    }

    /**
     * The output size in bytes of a tree digest, the security parameter n.
     */
    public static int getDigestSize(ASN1ObjectIdentifier oid)
    {
        return DigestUtil.getDigest(oid).getDigestSize();
    }

    /**
     * A tree digest by its OID. Note the SP 800-208 SHAKE256/192 and SHAKE256/256 parameter sets
     * name id-shake256-len, which no other algorithm in this package uses.
     */
    public static Digest getDigest(ASN1ObjectIdentifier oid)
    {
        return DigestUtil.getDigest(oid);
    }

    /**
     * The number of n-byte elements in a WOTS+ key or signature, len = len1 + len2 (RFC 8391
     * sec. 3.1.1). Rejects a tree digest and security parameter that are not a registered WOTS+
     * combination, which is where an unusable XMSS parameter set is caught.
     */
    public static int getWOTSPlusLen(ASN1ObjectIdentifier treeDigestOID, int digestSize)
    {
        return new WOTSPlusParameters(treeDigestOID, digestSize).getLen();
    }

    /**
     * The RFC 8391 sec. 5.3 XMSS parameter-set identifier for this combination, or 0 when the
     * combination is not one of the registered sets.
     */
    public static int lookupXMSSOid(String treeDigest, int digestSize, int winternitzParameter, int len, int height)
    {
        DefaultXMSSOid oid = DefaultXMSSOid.lookup(treeDigest, digestSize, winternitzParameter, len, height);

        return (oid != null) ? oid.getOid() : 0;
    }

    /**
     * The RFC 8391 sec. 5.4 XMSS^MT parameter-set identifier for this combination, or 0 when the
     * combination is not one of the registered sets.
     */
    public static int lookupXMSSMTOid(String treeDigest, int digestSize, int winternitzParameter, int len,
                                      int height, int layers)
    {
        DefaultXMSSMTOid oid = DefaultXMSSMTOid.lookup(treeDigest, digestSize, winternitzParameter, len, height, layers);

        return (oid != null) ? oid.getOid() : 0;
    }

    /**
     * Generate an XMSS key pair (RFC 8391 sec. 4.1.7).
     */
    public static AsymmetricCipherKeyPair generateKeyPair(XMSSParameters params, SecureRandom prng)
    {
        int n = params.getTreeDigestSize();
        byte[] secretKeySeed = new byte[n];
        prng.nextBytes(secretKeySeed);
        byte[] secretKeyPRF = new byte[n];
        prng.nextBytes(secretKeyPRF);
        byte[] publicSeed = new byte[n];
        prng.nextBytes(publicSeed);

        BDS bdsState = new BDS(params, publicSeed, secretKeySeed, XMSSAddress.otsHashAddress(0, 0L, 0));
        byte[] root = bdsState.getRoot().getValue();

        XMSSPrivateKeyParameters privateKey = new XMSSPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF)
            .withPublicSeed(publicSeed).withRoot(root)
            .withBDSState(bdsState).build();

        XMSSPublicKeyParameters publicKey = new XMSSPublicKeyParameters.Builder(params).withRoot(root)
            .withPublicSeed(publicSeed).build();

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    /**
     * Generate an XMSS^MT key pair (RFC 8391 sec. 4.2.5).
     */
    public static AsymmetricCipherKeyPair generateMTKeyPair(XMSSMTParameters params, SecureRandom prng)
    {
        XMSSParameters xmssParams = params.getXMSSParameters();

        int n = params.getTreeDigestSize();
        byte[] secretKeySeed = new byte[n];
        prng.nextBytes(secretKeySeed);
        byte[] secretKeyPRF = new byte[n];
        prng.nextBytes(secretKeyPRF);
        byte[] publicSeed = new byte[n];
        prng.nextBytes(publicSeed);

        BDSStateMap bdsState = new BDSStateMap((1L << params.getHeight()) - 1);

        /* get root */
        int rootLayerIndex = params.getLayers() - 1;
        byte[] otsAddress = XMSSAddress.otsHashAddress(rootLayerIndex, 0L, 0);

        /* store BDS instance of root xmss instance */
        BDS bdsRoot = new BDS(xmssParams, publicSeed, secretKeySeed, otsAddress);
        byte[] root = bdsRoot.getRoot().getValue();
        bdsState.put(rootLayerIndex, bdsRoot);

        /* set XMSS^MT root / create public key */
        XMSSMTPrivateKeyParameters privateKey = new XMSSMTPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed)
            .withRoot(root).withBDSState(bdsState).build();
        XMSSMTPublicKeyParameters publicKey = new XMSSMTPublicKeyParameters.Builder(params).withRoot(root)
            .withPublicSeed(publicSeed).build();

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    /**
     * Whether the key's BDS traversal state has been initialised, i.e. whether it can sign. A key
     * decoded from an encoding that carried no traversal state has none.
     * <p>
     * This and the XMSS^MT overload below are the only place the question is asked. What counts as
     * no state differs between the two families - a lone BDS with no authentication path, a state
     * map with no layers in it - and the signature methods below had a copy of the answer for
     * their own family inlined beside the copy the signers were already calling, so widening what
     * counts would have had to be applied to a public helper and to two private call sites that
     * did not go through it.
     * </p>
     */
    public static boolean hasTraversalState(XMSSPrivateKeyParameters privateKey)
    {
        return !privateKey.getBDSState().isAuthenticationPathEmpty();
    }

    /**
     * Whether the key's BDS traversal state has been initialised, i.e. whether it can sign.
     */
    public static boolean hasTraversalState(XMSSMTPrivateKeyParameters privateKey)
    {
        return !privateKey.getBDSState().isEmpty();
    }

    /**
     * Generate an XMSS signature over {@code message} and advance the key's traversal state
     * (RFC 8391 sec. 4.1.9).
     * <p>
     * The key is held locked across the whole check, sign and advance sequence. RFC 8391 sec. 1.1
     * requires each one-time key to be used exactly once, and this method both reads the index and
     * rolls the key past it: two threads entering with the same key and nothing serializing them
     * sign different messages under the same one-time key, and a WOTS+ key used twice discloses
     * enough of itself to forge. The key's own accessors are individually synchronized, which does
     * not make the compound sequence atomic, so the lock is taken here rather than left to the
     * caller - this is a public entry point and cannot assume one. {@code XMSSSigner} holds the
     * same monitor and Java monitors are reentrant, so that path is unchanged; LMS takes the
     * equivalent lock inside the key itself.
     * </p>
     */
    public static byte[] generateSignature(XMSSPrivateKeyParameters privateKey, byte[] message)
    {
        synchronized (privateKey)
        {
            return doGenerateSignature(privateKey, message);
        }
    }

    private static byte[] doGenerateSignature(XMSSPrivateKeyParameters privateKey, byte[] message)
    {
        XMSSParameters params = privateKey.getParameters();
        WOTSPlus wotsPlus = newWOTSPlus(params);
        KeyedHashFunctions khf = wotsPlus.getKhf();

        if (privateKey.getUsagesRemaining() <= 0)
        {
            throw new ExhaustedPrivateKeyException("no usages of private key remaining");
        }
        if (!hasTraversalState(privateKey))
        {
            throw new IllegalStateException("not initialized");
        }
        //
        // the read side of the markUsed() below, which until now nothing performed: a state that
        // has signed is replaced by the rollKey() beside it, so a key still holding a marked one
        // did not come from this engine - it was captured from a live key through getBDSState()
        // before the signature that spent it, or restored from an encoding written that way, and
        // both put the key back on an index it has already used. RFC 8391 sec. 1.1 makes signing
        // there a private key compromise, so it is refused here rather than reported by the
        // signature. Ahead of the try, as the two checks above are: a refused signature must not
        // reach the finally that rolls the key.
        //
        if (privateKey.getBDSState().isUsed())
        {
            throw new IllegalStateException(
                "one time key at index " + privateKey.getIndex() + " has already signed");
        }
        //
        // and here for the same reason. The secret material the try reads is zeroized, so the
        // signature would fail part way through it and reach the finally, where markUsed() would
        // mark a state no signature used and rollKey() would refuse the destroyed key in its turn -
        // replacing the exception the try raised with its own.
        //
        if (privateKey.isDestroyed())
        {
            throw new IllegalStateException("key destroyed");
        }

        try
        {
            int index = privateKey.getIndex();

            /* create (randomized keyed) messageDigest of message */
            byte[] random = khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(index, 32));
            byte[] concatenated = hMsgKey(random, privateKey.getRoot(), index,
                params.getTreeDigestSize());
            byte[] messageDigest = khf.HMsg(concatenated, message);

            /* create signature for messageDigest */
            byte[] otsAddress = XMSSAddress.otsHashAddress(0, 0L, index);
            byte[][] wotsPlusSignature = wotsSign(wotsPlus, privateKey.getSecretKeySeed(),
                privateKey.getPublicSeed(), messageDigest, otsAddress);

            return new XMSSSignature.Builder(params).withIndex(index).withRandom(random)
                .withWOTSPlusSignature(wotsPlusSignature)
                .withAuthPath(privateKey.getBDSState().getAuthenticationPath())
                .build().toByteArray();
        }
        finally
        {
            privateKey.getBDSState().markUsed();
            privateKey.rollKey();
        }
    }

    /**
     * Verify an XMSS signature (RFC 8391 sec. 4.1.10). A signature that will not decode at all is
     * reported as a failed verification rather than raised, per the JCA contract the signers above
     * this present. An absent one is not the same thing: there are no bytes to decode, so a null
     * signature is the caller's mistake and is raised.
     */
    public static boolean verifySignature(XMSSPublicKeyParameters publicKey, byte[] message, byte[] signature)
    {
        // ahead of the decode below, whose catch would otherwise fold a missing argument into the
        // same false a malformed one gets: the builder reads the array's length to check it against
        // the size these parameters fix, and the NullPointerException that dereference raises is
        // indistinguishable there from what a bad encoding raises
        if (signature == null)
        {
            throw new NullPointerException("signature == null");
        }

        XMSSParameters params = publicKey.getParameters();
        WOTSPlus wotsPlus = newWOTSPlus(params);
        KeyedHashFunctions khf = wotsPlus.getKhf();

        XMSSSignature sig;
        try
        {
            sig = new XMSSSignature.Builder(params).withSignature(signature).build();
        }
        catch (RuntimeException e)
        {
            // malformed/truncated signature: do not propagate ArrayIndexOutOfBoundsException
            // (short header) or IllegalArgumentException (wrong length)
            return false;
        }

        int index = sig.getIndex();

        /* reinitialize WOTS+ object */
        wotsPlus.importKeys(new byte[params.getTreeDigestSize()], publicKey.getPublicSeed());

        // read once. A verification wants the root twice - as the middle of the H_msg key, and as
        // what the root climbed out of the signature is compared against - and getRoot() hands out
        // a clone each time, so the second call was a second n-byte copy of a field written at
        // construction and never after. Reading it once is also what makes the two uses provably
        // the same bytes rather than two reads that happen not to be able to differ.
        byte[] root = publicKey.getRoot();

        /* create message digest */
        byte[] concatenated = hMsgKey(sig.getRandom(), root, index, params.getTreeDigestSize());
        byte[] messageDigest = khf.HMsg(concatenated, message);

        int xmssHeight = params.getHeight();
        int indexLeaf = XMSSUtil.getLeafIndex(index, xmssHeight);

        /* get root from signature */
        byte[] otsAddress = XMSSAddress.otsHashAddress(0, 0L, index);
        XMSSNode rootNodeFromSignature = XMSSVerifierUtil.getRootNodeFromSignature(wotsPlus, xmssHeight, messageDigest,
            sig, otsAddress, indexLeaf);

        return Arrays.constantTimeAreEqual(rootNodeFromSignature.getValue(), root);
    }

    /**
     * Generate an XMSS^MT signature over {@code message} and advance the key's traversal state
     * (RFC 8391 sec. 4.2.7). The key is held locked for the whole sequence, for the reason given on
     * {@link #generateSignature(XMSSPrivateKeyParameters, byte[])}.
     */
    public static byte[] generateMTSignature(XMSSMTPrivateKeyParameters privateKey, byte[] message)
    {
        synchronized (privateKey)
        {
            return doGenerateMTSignature(privateKey, message);
        }
    }

    private static byte[] doGenerateMTSignature(XMSSMTPrivateKeyParameters privateKey, byte[] message)
    {
        XMSSMTParameters params = privateKey.getParameters();
        XMSSParameters xmssParams = params.getXMSSParameters();
        WOTSPlus wotsPlus = newWOTSPlus(params);

        if (privateKey.getUsagesRemaining() <= 0)
        {
            throw new ExhaustedPrivateKeyException("no usages of private key remaining");
        }
        if (!hasTraversalState(privateKey))
        {
            throw new IllegalStateException("not initialized");
        }
        //
        // as the XMSS path above, on the layer zero state - the one whose leaf signs the message,
        // and so the one a second signature must never reuse. The allowance is the same one
        // BDSStateMap.validate(params, globalIndex) makes: on the first leaf of a subtree the
        // signer builds layer zero fresh, so the marked state carried over from the end of the
        // previous subtree is legitimate there and is about to be thrown away.
        //
        if (XMSSUtil.getLeafIndex(privateKey.getIndex(), xmssParams.getHeight()) != 0
            && privateKey.getBDSState().isUsed())
        {
            throw new IllegalStateException(
                "one time key at index " + privateKey.getIndex() + " has already signed");
        }
        //
        // and the other half of the same question. The check above asks whether the layer zero
        // state has signed where it stands; this asks whether it is standing where the key says it
        // is. XMSS^MT records its position twice - the index field, and the per-layer states - and
        // they are advanced by separate statements, so a key can be holding two answers; the
        // constructor, rollKey() and both encoders all compare them, and this, the one place that
        // spends a one-time key, did not. What reaches here with them apart is a state map put back
        // into a live key through getBDSState(), or a key half restored: the signature it makes is
        // built for the leaf the index names and carries the authentication path of the leaf the
        // state is on, so it consumes a one-time key and does not verify. github #2414 and the
        // position-stored-twice rule it left behind; the single tree needs no counterpart, its
        // index being the BDS state's own. Ahead of the try below, as the checks above are: a
        // refused signature must not reach the roll.
        //
        privateKey.getBDSState().validateIndex(params, privateKey.getIndex(), privateKey.getPublicSeed(),
            privateKey.getSecretKeySeed());

        //
        // and here for the reason the single tree gives: the secret material the descent below
        // reads is zeroized, so the signature would fail part way through it and reach the finally,
        // where markUsed() would mark a state no signature used and rollKey() would refuse the
        // destroyed key in its turn - replacing the exception it raised with its own.
        //
        if (privateKey.isDestroyed())
        {
            throw new IllegalStateException("key destroyed");
        }

        //
        // the map's own monitor, held for the whole descent below and the roll that follows it.
        // This is the writer BDSStateMap's own javadoc is about: the layer states built below are
        // installed into the live map with put(), and a caller copying that map does not hold the
        // key's monitor, having reached the map through getBDSState(). Lock order is always key
        // then map; nothing takes them the other way round, a state map holding no reference to a
        // key.
        //
        BDSStateMap bdsState = privateKey.getBDSState();

        synchronized (bdsState)
        {
            try
            {
                byte[] publicSeed = privateKey.getPublicSeed();
                byte[] secretKeySeed = privateKey.getSecretKeySeed();

                final long globalIndex = privateKey.getIndex();
                final int xmssHeight = xmssParams.getHeight();

                /* compress message */
                byte[] random = wotsPlus.getKhf().PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(globalIndex, 32));
                byte[] concatenated = hMsgKey(random, privateKey.getRoot(), globalIndex,
                    params.getTreeDigestSize());
                byte[] messageDigest = wotsPlus.getKhf().HMsg(concatenated, message);

                XMSSMTSignature signature = new XMSSMTSignature.Builder(params).withIndex(globalIndex).withRandom(random).build();

                /* layer 0 */
                long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
                int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);

                /* reset xmss */
                wotsPlus.importKeys(new byte[params.getTreeDigestSize()], publicSeed);

                /* create signature with XMSS tree on layer 0 */

                /* adjust addresses */
                byte[] otsAddress = XMSSAddress.otsHashAddress(0, indexTree, indexLeaf);

                /* get authentication path from BDS */
                if (bdsState.get(0) == null || indexLeaf == 0)
                {
                    bdsState.put(0, new BDS(xmssParams, publicSeed, secretKeySeed, otsAddress));
                }

                /* sign message digest */
                byte[][] wotsPlusSignature = wotsSign(wotsPlus, secretKeySeed,
                    publicSeed, messageDigest, otsAddress);

                XMSSReducedSignature reducedSignature = new XMSSReducedSignature.Builder(xmssParams)
                    .withWOTSPlusSignature(wotsPlusSignature).withAuthPath(bdsState.get(0).getAuthenticationPath())
                    .build();

                signature.getReducedSignatures().add(reducedSignature);

                /* loop over remaining layers */
                for (int layer = 1; layer < params.getLayers(); layer++)
                {
                    /* get root of layer - 1 */
                    XMSSNode root = bdsState.get(layer - 1).getRoot();

                    indexLeaf = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
                    indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);

                    /* adjust addresses */
                    otsAddress = XMSSAddress.otsHashAddress(layer, indexTree, indexLeaf);

                    /* sign root digest of layer - 1 */
                    wotsPlusSignature = wotsSign(wotsPlus, secretKeySeed,
                        publicSeed, root.getValue(), otsAddress);

                    /* get authentication path from BDS */
                    if (bdsState.get(layer) == null || XMSSUtil.isNewBDSInitNeeded(globalIndex, xmssHeight, layer))
                    {
                        bdsState.put(layer, new BDS(xmssParams, publicSeed, secretKeySeed, otsAddress));
                    }

                    reducedSignature = new XMSSReducedSignature.Builder(xmssParams)
                        .withWOTSPlusSignature(wotsPlusSignature)
                        .withAuthPath(bdsState.get(layer).getAuthenticationPath()).build();

                    signature.getReducedSignatures().add(reducedSignature);
                }

                return signature.toByteArray();
            }
            finally
            {
                bdsState.markUsed();
                privateKey.rollKey();
            }
        }
    }

    /**
     * Verify an XMSS^MT signature (RFC 8391 sec. 4.2.8). As with XMSS above, a signature that will
     * not decode is reported as a failed verification rather than raised, and an absent one is
     * raised.
     */
    public static boolean verifyMTSignature(XMSSMTPublicKeyParameters publicKey, byte[] message, byte[] signature)
    {
        // ahead of the decode below, which a null does not fail: the builder takes a null signature
        // as a request for its set-the-fields branch instead, so what it returns is a signature with
        // no reduced signatures at all, and that reached the layer-0 get() further down - outside
        // the catch - as an IndexOutOfBoundsException
        if (signature == null)
        {
            throw new NullPointerException("signature == null");
        }

        XMSSMTParameters params = publicKey.getParameters();
        XMSSParameters xmssParams = params.getXMSSParameters();
        WOTSPlus wotsPlus = newWOTSPlus(params);

        XMSSMTSignature sig;
        try
        {
            sig = new XMSSMTSignature.Builder(params).withSignature(signature).build();
        }
        catch (RuntimeException e)
        {
            // malformed/truncated signature: do not propagate IllegalArgumentException
            return false;
        }

        // read once, as in verifySignature above and for the same reason
        byte[] root = publicKey.getRoot();

        byte[] concatenated = hMsgKey(sig.getRandom(), root, sig.getIndex(),
            params.getTreeDigestSize());
        byte[] messageDigest = wotsPlus.getKhf().HMsg(concatenated, message);

        long globalIndex = sig.getIndex();
        int xmssHeight = xmssParams.getHeight();
        long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
        int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);

        /* adjust xmss */
        wotsPlus.importKeys(new byte[params.getTreeDigestSize()], publicKey.getPublicSeed());

        /* prepare addresses */
        byte[] otsAddress = XMSSAddress.otsHashAddress(0, indexTree, indexLeaf);

        /* get root node on layer 0 */
        XMSSReducedSignature xmssMTSignature = sig.getReducedSignatures().get(0);
        XMSSNode rootNode = XMSSVerifierUtil.getRootNodeFromSignature(wotsPlus, xmssHeight, messageDigest,
            xmssMTSignature, otsAddress, indexLeaf);
        for (int layer = 1; layer < params.getLayers(); layer++)
        {
            xmssMTSignature = sig.getReducedSignatures().get(layer);
            indexLeaf = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
            indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);

            /* adjust address */
            otsAddress = XMSSAddress.otsHashAddress(layer, indexTree, indexLeaf);

            /* get root node */
            rootNode = XMSSVerifierUtil.getRootNodeFromSignature(wotsPlus, xmssHeight, rootNode.getValue(),
                xmssMTSignature, otsAddress, indexLeaf);
        }

        /* compare roots */
        return Arrays.constantTimeAreEqual(rootNode.getValue(), root);
    }

    /**
     * A fresh BDS traversal state for a key at {@code index}, built at the all-zero OTS hash
     * address an XMSS key starts from.
     *
     * @throws IllegalArgumentException if {@code index} is out of range for the parameter set.
     */
    public static BDS createBDS(XMSSParameters params, byte[] publicSeed, byte[] secretKeySeed, int index)
    {
        int height = params.getHeight();

        // the state is reached by walking the tree one authentication path at a time, so an index
        // out of range has to be refused before the walk rather than by the walk: it would otherwise
        // cost a full tree of authentication paths - 2^h - 1 of them - to arrive at the same answer,
        // which at the RFC 8391 heights is minutes of work at h = 16 and hours at h = 20. This is
        // the check the encoded-key path (XMSSPrivateKeyParameters) makes on the index it reads, and
        // the one XMSSMTPrivateKeyParameters already made before building a state map.
        if (!isStoredIndexValid(height, index))
        {
            throw new IllegalArgumentException("index out of bounds");
        }

        int maxIndex = (1 << height) - 1;

        if (index > maxIndex)
        {
            // every leaf is spent. There is no traversal state to walk to - the walk would step off
            // the end of the tree - and this is the state rollKey() leaves behind at the same point.
            return new BDS(params, maxIndex, index);
        }

        return new BDS(params, publicSeed, secretKeySeed, XMSSAddress.otsHashAddress(0, 0L, 0), index);
    }

    /**
     * A fresh BDS traversal state map for an XMSS^MT key at {@code globalIndex}, the multi-tree
     * counterpart of {@link #createBDS(XMSSParameters, byte[], byte[], int)}.
     * <p>
     * The map a key at index 0 gets is empty, and stays that way until a signature needs a layer:
     * XMSS^MT builds each layer's state lazily. So an empty map is not a missing one, and nothing
     * downstream can tell an out-of-range index by looking at what this returns - the structural
     * check in {@code BDSStateMap.validate()} passes over a map with no layers in it, and the
     * index check walks the layers it does have. That is what makes the bound here the only place
     * the index is answered, rather than one of two.
     * </p>
     *
     * @throws IllegalArgumentException if {@code globalIndex} is out of range for the parameter set.
     */
    public static BDSStateMap createBDSStateMap(XMSSMTParameters params, byte[] publicSeed, byte[] secretKeySeed,
        long globalIndex)
    {
        int totalHeight = params.getHeight();

        if (!isStoredIndexValid(totalHeight, globalIndex))
        {
            throw new IllegalArgumentException("index out of bounds");
        }

        long maxIndex = (1L << totalHeight) - 1;

        if (globalIndex > maxIndex)
        {
            // every leaf of the hypertree is spent, and this is the state rollKey() leaves behind
            // at the same point - as on the single-tree side, where createBDS says the same.
            return new BDSStateMap(maxIndex);
        }

        return new BDSStateMap(params, globalIndex, publicSeed, secretKeySeed);
    }

    /**
     * The traversal state for the next index, i.e. with the authentication path advanced one leaf.
     */
    public static BDS getNextBDSState(BDS bdsState, byte[] publicSeed, byte[] secretKeySeed)
    {
        return bdsState.getNextState(publicSeed, secretKeySeed, XMSSAddress.otsHashAddress(0, 0L, 0));
    }

    /**
     * The BDS traversal state as it is carried in an XMSS private key encoding, with its checksum
     * bound to the owning key's public seed (github #2414). The form is the versioned one
     * {@code BDSStateCodec} defines, and this is where every one written comes from: the key
     * parameters class reaches it for toByteArray() and for the state half of equals(), and
     * XmssKeyUtil for the PKCS#8 encoding.
     * <p>
     * The legacy Java-serialized form is a decode-side concern only. A key written before that
     * codec existed carries one and {@link #getBDSFromEncoding(byte[], byte[])} still reads it,
     * but nothing has written one since.
     * </p>
     */
    public static byte[] getEncodedBDSState(BDS bdsState, byte[] publicSeed)
        throws IOException
    {
        return XMSSUtil.serialize(bdsState, publicSeed);
    }

    /**
     * The BDS traversal state as it is carried in an XMSS^MT private key encoding, with its
     * checksum bound to the owning key's public seed (github #2414).
     */
    public static byte[] getEncodedBDSState(BDSStateMap bdsState, byte[] publicSeed)
        throws IOException
    {
        return XMSSUtil.serialize(bdsState, publicSeed);
    }

    /**
     * Zeroize the secret material a BDS traversal state retains - the WOTS+ secret key its
     * hash-function instance imported for the last leaf it processed, which is a future leaf's
     * one-time key while the tree is not exhausted. The tree nodes are kept; they are not secret.
     * <p>
     * Here rather than as a public method on {@code BDS} because the state classes are the engine's
     * and the caller is {@code XMSSPrivateKeyParameters.destroy()} in another package: this is the
     * same reason {@link #getEncodedBDSState(BDS, byte[])} and {@link #hasTraversalState} sit here.
     * </p>
     */
    public static void clearSecrets(BDS bdsState)
    {
        bdsState.clearSecrets();
    }

    /**
     * Zeroize the secret material retained by every layer of an XMSS^MT traversal state; see
     * {@link #clearSecrets(BDS)}.
     */
    public static void clearSecrets(BDSStateMap bdsState)
    {
        bdsState.clearSecrets();
    }

    /**
     * The XMSS^MT traversal state for the leaf after {@code globalIndex}, for the key parameters
     * class rolling its own key on. The state passed in is left where it is and a new one comes
     * back, as {@link #getNextBDSState} does for the single tree.
     * <p>
     * That it returns the advanced state rather than advancing the one it is given is what makes it
     * safe to be public - and public it has to be, the key parameters class being in another
     * package and Java having no way to say "callable from these two packages only". A state map is
     * reachable from a live private key through its getBDSState(), so a version of this that
     * advanced its argument let a holder move a key's state out from under the index the key still
     * reported. A key whose two records of its position disagree signs a second message under a
     * one-time key it has already spent, against RFC 8391 sec. 1.1, and that signature verifies.
     * </p><p>
     * With the state replaced instead, the two records move together or not at all: the key assigns
     * both, a failure part way through leaves it on the index it was already on, and a holder
     * calling this gets a state map of its own while the key keeps the one it had. Nothing is left
     * for the signer to check, and the one remaining way for a key's index and state to part - a
     * stored key written or restored wrongly - is refused when the key is built.
     * </p>
     */
    public static BDSStateMap getNextBDSStateMap(BDSStateMap bdsState, XMSSMTParameters params, long globalIndex,
        byte[] publicSeed, byte[] secretKeySeed)
    {
        return bdsState.getNextState(params, globalIndex, publicSeed, secretKeySeed);
    }

    /**
     * Recover an XMSS BDS traversal state from a private key encoding, checking its checksum
     * against the owning key's public seed (github #2414).
     */
    public static BDS getBDSFromEncoding(byte[] encoding, byte[] publicSeed)
        throws IOException, ClassNotFoundException
    {
        return (BDS)XMSSUtil.deserialize(encoding, BDS.class, publicSeed);
    }

    /**
     * Recover an XMSS^MT BDS traversal state from a private key encoding, checking its checksum
     * against the owning key's public seed (github #2414).
     */
    public static BDSStateMap getBDSStateMapFromEncoding(byte[] encoding, byte[] publicSeed)
        throws IOException, ClassNotFoundException
    {
        return (BDSStateMap)XMSSUtil.deserialize(encoding, BDSStateMap.class, publicSeed);
    }

    /**
     * Whether {@code index} is in range for the index field of a stored private key over a tree of
     * this height, i.e. 0 &lt;= index &lt;= 2^height.
     * <p>
     * The bound is one leaf wider than the 0 &lt;= index &lt; 2^height an index a signature can
     * be made at satisfies, because a key that has been used up carries the index one past its
     * last leaf: that is the placeholder traversal state
     * {@link BDS} installs when the final one-time key is consumed, it is what makes the key report
     * no usages remaining, and both {@code BDS.validate()} and the BDS serialization admit it. A
     * key's final state is the one state that most needs to survive being written out and read
     * back, so the private key encoding has to carry it rather than reject it. The tighter bound
     * against the key's own maximum index is applied by {@code BDS.validate()} once the traversal
     * state itself has been recovered.
     * </p>
     */
    public static boolean isStoredIndexValid(int height, long index)
    {
        return index >= 0 && index <= (1L << height);
    }

    /**
     * The key H_msg is applied under when a message is compressed, r || root || toByte(idx_sig, n)
     * of RFC 8391 sec. 4.1.9 and 4.2.7, built straight into the one 3n-byte array
     * {@link KeyedHashFunctions#HMsg} reads.
     * <p>
     * The four call sites - sign and verify, XMSS and XMSS^MT - had each written this as an
     * Arrays.concatenate of three pieces, the last of which was an n-byte array that
     * XMSSUtil.toBytesBigEndian allocated only for concatenate to copy in and drop. The index is
     * written here in place instead, over the zeros a fresh array already carries.
     * <p>
     * Taking n of r and n of root rather than however many each happens to hold is not a new
     * assumption: r is a PRF output or a signature field the builder took at exactly n, and root
     * is a key field validateOrAllocate pinned there, so all four sites already had both at n.
     * What changes is that one that somehow were not would fail here rather than quietly produce a
     * key of another length for H_msg to hash. The min is toBytesBigEndian's, kept so the two say
     * the same thing about a size under eight bytes; no parameter set WOTSPlusOid admits comes
     * near that.
     */
    private static byte[] hMsgKey(byte[] random, byte[] root, long index, int n)
    {
        byte[] concatenated = new byte[3 * n];
        System.arraycopy(random, 0, concatenated, 0, n);
        System.arraycopy(root, 0, concatenated, n, n);
        int len = Math.min(n, 8);
        Pack.longToBigEndian_Low(index, concatenated, (3 * n) - len, len);
        return concatenated;
    }

    /**
     * Return {@code value} once it is confirmed to be {@code size} bytes long, or a freshly
     * allocated all-zero array of that size if {@code value} is null. {@code name} is how the
     * field is named in the message a wrong-sized one is refused with.
     * <p>
     * Shared by the four key parameter classes and the two signature classes, which take their
     * optional n-byte fields on the same terms and so must say the same thing about one that is
     * the wrong size.
     * </p>
     */
    public static byte[] validateOrAllocate(byte[] value, int size, String name)
    {
        return XMSSUtil.validateOrAllocate(value, size, name);
    }

    /**
     * Refuse a request for a key shard of {@code usageCount} signatures from a key with
     * {@code usagesRemaining} left: a shard of none, and a shard of more than the key has.
     * <p>
     * Shared by the two private key classes, which mean the same thing by both and had said it in
     * the same words twice - and the words are the contract, since a message is what a caller
     * catching IllegalArgumentException has to tell the two cases apart by. Beside
     * validateOrAllocate above for the same reason it is here: the four key classes and the two
     * signature classes take their optional n-byte fields on the same terms, and this is the
     * terms both key classes hand out a shard on.
     * </p>
     *
     * @param usageCount      signatures asked for.
     * @param usagesRemaining signatures the key has left, read under the key's own monitor.
     */
    public static void validateShardSize(int usageCount, long usagesRemaining)
    {
        if (usageCount < 1)
        {
            throw new IllegalArgumentException("cannot ask for a shard with 0 keys");
        }
        if (usageCount > usagesRemaining)
        {
            throw new IllegalArgumentException("usageCount exceeds usages remaining");
        }
    }

    static WOTSPlus newWOTSPlus(XMSSParameters params)
    {
        return new WOTSPlus(newWOTSPlusParameters(params));
    }

    static WOTSPlusParameters newWOTSPlusParameters(XMSSParameters params)
    {
        return new WOTSPlusParameters(params.getTreeDigestOID(), params.getTreeDigestSize());
    }

    static WOTSPlus newWOTSPlus(XMSSMTParameters params)
    {
        return newWOTSPlus(params.getXMSSParameters());
    }

    /**
     * Signs the n-byte messageDigest with the one-time key at the given OTS hash address.
     * <p>
     * The length is checked against the WOTS+ instance's own n - the one khf and chain use - and
     * this is the only place it is checked: nothing downstream would catch a wrong length, since
     * convertToBaseW faults a digest that is too short ("outLength too big") but silently truncates
     * one that is too long, so two different digests could sign to the same signature. What reaches
     * here is either a khf.HMsg output, exactly n bytes by construction, or the root of a stored
     * BDS state, which BDS.validate(XMSSParameters) has already pinned to non-null and exactly n
     * before the key holding it could be constructed.
     */
    private static byte[][] wotsSign(WOTSPlus wotsPlus, byte[] secretKeySeed,
                                     byte[] publicSeed, byte[] messageDigest, byte[] otsAddress)
    {
        if (messageDigest.length != wotsPlus.getParams().getTreeDigestSize())
        {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        /* (re)initialize WOTS+ instance */
        wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretKeySeed, otsAddress), publicSeed);

        /* create WOTS+ signature */
        return wotsPlus.sign(messageDigest, otsAddress);
    }
}
