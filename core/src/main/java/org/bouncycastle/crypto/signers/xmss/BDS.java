package org.bouncycastle.crypto.signers.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import java.util.TreeMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * BDS.
 */
public final class BDS
    implements Serializable
{
    private static final long serialVersionUID = 1L;
    
    private final transient WOTSPlus wotsPlus;

    private final int treeHeight;
    private final List<BDSTreeHash> treeHashInstances;
    private final int k;
    private XMSSNode root;
    private final List<XMSSNode> authenticationPath;
    private final Map<Integer, List<XMSSNode>> retain;
    private final Stack<XMSSNode> stack;

    private final Map<Integer, XMSSNode> keep;
    private int index;
    private boolean used;

    private transient int maxIndex;

    /**
     * Place holder BDS for when state is exhausted.
     *
     * @param params tree parameters
     * @param index the index that has been reached.
     */
    public BDS(XMSSParameters params, int maxIndex, int index)
    {
        this(XMSSEngine.newWOTSPlus(params), params.getHeight(), params.getK(), index);
        this.maxIndex = maxIndex;
        this.index = index;
        this.used = true;
    }

    /**
     * Set up constructor.
     *
     * @param params tree parameters
     * @param publicSeed public seed for tree
     * @param secretKeySeed secret seed for tree
     * @param otsAddress the 32-byte encoding of the OTS hash address the tree starts at; read
     *                   and never written, see {@link #initialize}.
     */
    BDS(XMSSParameters params, byte[] publicSeed, byte[] secretKeySeed, byte[] otsAddress)
    {
        this(XMSSEngine.newWOTSPlus(params), params.getHeight(), params.getK(), ((1 << params.getHeight()) - 1));
        this.initialize(publicSeed, secretKeySeed, otsAddress);
    }

    /**
     * Set up constructor for a tree where the original BDS state was lost.
     *
     * @param params tree parameters
     * @param publicSeed public seed for tree
     * @param secretKeySeed secret seed for tree
     * @param otsAddress the 32-byte encoding of the OTS hash address the tree starts at; read
     *                   and never written, see {@link #initialize}.
     * @param index index counter for the state to be at.
     */
    BDS(XMSSParameters params, byte[] publicSeed, byte[] secretKeySeed, byte[] otsAddress, int index)
    {
        this(XMSSEngine.newWOTSPlus(params), params.getHeight(), params.getK(), ((1 << params.getHeight()) - 1));

        this.initialize(publicSeed, secretKeySeed, otsAddress);

        while (this.index < index)
        {
            this.nextAuthenticationPath(publicSeed, secretKeySeed, otsAddress);
            this.used = false;
        }
    }

    private BDS(WOTSPlus wotsPlus, int treeHeight, int k, int maxIndex)
    {
        this.wotsPlus = wotsPlus;
        this.treeHeight = treeHeight;
        this.maxIndex = maxIndex;
        this.k = k;
        if (k > treeHeight || k < 2 || ((treeHeight - k) % 2) != 0)
        {
            throw new IllegalArgumentException("illegal value for BDS parameter k");
        }
        authenticationPath = new ArrayList<XMSSNode>();
        retain = new TreeMap<Integer, List<XMSSNode>>();
        stack = new Stack<XMSSNode>();

        treeHashInstances = new ArrayList<BDSTreeHash>();
        for (int height = 0; height < (treeHeight - k); height++)
        {
            treeHashInstances.add(new BDSTreeHash(height));
        }

        keep = new TreeMap<Integer, XMSSNode>();
        index = 0;
        this.used = false;
    }

    /**
     * A state assembled field by field, for a decoder that has just read one.
     * <p>
     * The five collections are adopted rather than copied, so the caller hands them over and must
     * not go on using them. That is what a decoder is holding: {@code BDSStateCodec.readBDS} makes
     * each of them a node at a time out of the stream and has the only reference to it, so a copy
     * taken here allocated a second whole traversal state - the five containers, the queues inside
     * retain and a clone of every tree hash instance - on the path every private key decode takes,
     * to protect a caller that had nothing left to protect.
     * </p><p>
     * The constructors that carry a state on from another one still copy, because there the other
     * one goes on being used; see {@link #BDS(BDS)} and the block above the getLive accessors.
     * </p>
     */
    BDS(int treeHeight, int k, int maxIndex, int index, boolean used, XMSSNode root,
        List<XMSSNode> authenticationPath, Map<Integer, List<XMSSNode>> retain,
        Stack<XMSSNode> stack, List<BDSTreeHash> treeHashInstances, Map<Integer, XMSSNode> keep)
    {
        this.wotsPlus = null;
        this.treeHeight = treeHeight;
        this.k = k;
        this.maxIndex = maxIndex;
        this.index = index;
        this.used = used;
        this.root = root;
        this.authenticationPath = authenticationPath;
        this.retain = retain;
        this.stack = stack;
        this.treeHashInstances = treeHashInstances;
        this.keep = keep;
        this.validate();
    }

    /**
     * The copy the four "carry on from a previous state" constructors below all make, written
     * once. Each of them differs from the others only in the WOTS+ instance it ends up with,
     * whether it keeps the maximum index and the used mark of the state it copies, and what it
     * does after the copy - so those are the arguments, and the rest is this.
     * <p>
     * They had a copy of the block each, which is how a field added to the traversal state has to
     * be threaded through four places by hand: that happened once already, for maxIndex, and
     * missing one of the four leaves that constructor quietly building a state whose new field
     * never came across. Two of the four end in validate(), which would have caught it, and two -
     * the plain copy and the one the signer advances through, both on the per signature path - do
     * not, so the way not to have the problem is to have one copy rather than to check four.
     * </p>
     */
    private BDS(BDS last, WOTSPlus wotsPlus, int maxIndex, boolean used)
    {
        this.wotsPlus = wotsPlus;
        this.treeHeight = last.treeHeight;
        this.k = last.k;
        this.root = last.root;
        this.authenticationPath = cloneAuthenticationPath(last.authenticationPath);
        this.retain = cloneRetain(last.retain);
        this.stack = cloneStack(last.stack);
        this.treeHashInstances = cloneTreeHashInstances(last.treeHashInstances);
        this.keep = new TreeMap<Integer, XMSSNode>(last.keep);
        this.index = last.index;
        this.maxIndex = maxIndex;
        this.used = used;
    }

    /**
     * A plain copy of a state, its WOTS+ instance included where there is one to copy.
     * <p>
     * There need not be. The WOTS+ parameters are not part of what a state is serialized as, so a
     * state that has just been decoded carries none until {@link #withWOTSDigest} names the digest
     * and builds them, and this read them off the state being copied without asking - so copying a
     * decoded state was a NullPointerException, and the two operations had to be performed in one
     * order. A copy of a state that has not been given its digest yet is a state that has not been
     * given its digest yet, and can be given one exactly as the original could.
     * </p>
     */
    BDS(BDS last)
    {
        this(last, (last.wotsPlus != null) ? new WOTSPlus(last.wotsPlus.getParams()) : null,
            last.maxIndex, last.used);
    }

    private BDS(BDS last, byte[] publicSeed, byte[] secretKeySeed, byte[] otsAddress)
    {
        // the state being built is the one after last, and it has signed nothing yet
        this(last, new WOTSPlus(last.wotsPlus.getParams()), last.maxIndex, false);

        this.nextAuthenticationPath(publicSeed, secretKeySeed, otsAddress);
    }

    private BDS(BDS last, ASN1ObjectIdentifier digest, int digestSize)
    {
        this(last, newWOTSPlus(digest, digestSize), last.maxIndex, last.used);
        this.validate();
    }

    private BDS(BDS last, int maxIndex, ASN1ObjectIdentifier digest, int digestSize)
    {
        this(last, newWOTSPlus(digest, digestSize), maxIndex, last.used);
        this.validate();
    }

    /**
     * The WOTS+ instance the two constructors that rebuild a state around a named digest make -
     * a decoded state carries no WOTS+ parameters of its own, so they cannot take last's. An
     * explicit size is needed for the digests whose output length is not fixed by their name.
     */
    private static WOTSPlus newWOTSPlus(ASN1ObjectIdentifier digest, int digestSize)
    {
        return new WOTSPlus(digestSize > 0
            ? new WOTSPlusParameters(digest, digestSize) : new WOTSPlusParameters(digest));
    }

    // note use of addAll/clone rather than a shared reference to avoid serialization issues
    private static List<XMSSNode> cloneAuthenticationPath(List<XMSSNode> authenticationPath)
    {
        List<XMSSNode> clone = new ArrayList<XMSSNode>();
        clone.addAll(authenticationPath);
        return clone;
    }

    private static Map<Integer, List<XMSSNode>> cloneRetain(Map<Integer, List<XMSSNode>> retain)
    {
        Map<Integer, List<XMSSNode>> clone = new TreeMap<Integer, List<XMSSNode>>();
        for (Iterator it = retain.keySet().iterator(); it.hasNext();)
        {
            Integer key = (Integer)it.next();
            clone.put(key, new LinkedList<XMSSNode>(retain.get(key)));
        }
        return clone;
    }

    private static Stack<XMSSNode> cloneStack(Stack<XMSSNode> stack)
    {
        Stack<XMSSNode> clone = new Stack<XMSSNode>();
        clone.addAll(stack);
        return clone;
    }

    private static List<BDSTreeHash> cloneTreeHashInstances(List<BDSTreeHash> treeHashInstances)
    {
        List<BDSTreeHash> clone = new ArrayList<BDSTreeHash>();
        for (Iterator it = treeHashInstances.iterator(); it.hasNext();)
        {
            clone.add(((BDSTreeHash)it.next()).clone());
        }
        return clone;
    }

    BDS getNextState(byte[] publicSeed, byte[] secretKeySeed, byte[] otsAddress)
    {
        return new BDS(this, publicSeed, secretKeySeed, otsAddress);
    }

    /**
     * Zeroize the secret material this state retains: the WOTS+ secret key its hash-function
     * instance imported for the last leaf it processed, which is a future leaf's one-time key
     * while the tree is not exhausted. The tree nodes are kept - they are not secret. Called when
     * the enclosing private key is destroyed.
     * <p>
     * The instance can be absent: {@code wotsPlus} is transient, so a state that arrived through
     * Java deserialization carries none until it is rebuilt around the digest its key names.
     * </p>
     */
    void clearSecrets()
    {
        if (wotsPlus != null)
        {
            wotsPlus.clearSecretKeySeed();
        }
    }

    /**
     * Walk the whole tree, leaf by leaf, and leave this state holding its root and the
     * authentication path of leaf zero (RFC 8391 sec. 4.1.6 algorithm 9).
     *
     * @param otsAddress the 32-byte encoding of the OTS hash address the tree starts at. Read and
     *                   never written: the walk steps a copy of it, because a caller may go on to
     *                   use the same starting address - XMSSEngine.generateMTSignature signs with
     *                   it right after building this state - and the OTS address word of the copy
     *                   ends the walk at the last leaf of the tree.
     */
    private void initialize(byte[] publicSeed, byte[] secretSeed, byte[] otsAddress)
    {
        /* prepare addresses - one encoding each for the whole walk, with the words that change
         * written into them as it goes. The two below the leaf's are the same tree as it, so they
         * are taken from its encoding rather than assembled beside it. */
        byte[] leafAddress = Arrays.clone(otsAddress);
        byte[] lTreeAddress = XMSSAddress.subtreeAddressOf(otsAddress, XMSSAddress.LTREE_TYPE);
        byte[] hashTreeAddress = XMSSAddress.subtreeAddressOf(otsAddress, XMSSAddress.HASH_TREE_TYPE);
        /* and one pair of working buffers for every node hashed below, L-tree and tree alike; see
         * XMSSNodeUtil.randomizeHash for why one pair serves a whole walk */
        int n = wotsPlus.getParams().getTreeDigestSize();
        byte[] nodeKey = new byte[n];
        byte[] nodeMask = new byte[2 * n];

        /* iterate indexes */
        for (int indexLeaf = 0; indexLeaf < (1 << treeHeight); indexLeaf++)
        {
            /* generate leaf - the one word of the OTS encoding a leaf is named by, stepped through
             * the walk's own copy of it the way the two encodings above are stepped. What the
             * previous leaf's chains left in the three words below it is cleared by
             * getWOTSPlusSecretKey, which says so. */
            Pack.intToBigEndian(indexLeaf, leafAddress, XMSSAddress.OTS_ADDRESS_OFFSET);
            /*
             * import WOTSPlusSecretKey as its needed to calculate the public
             * key on the fly
             */
            wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretSeed, leafAddress), publicSeed);
            WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(leafAddress);
            Pack.intToBigEndian(indexLeaf, lTreeAddress, XMSSAddress.LTREE_ADDRESS_OFFSET);
            XMSSNode node = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPublicKey, lTreeAddress, nodeKey, nodeMask);

            // the two words of the hash tree encoding the climb below moves, kept beside it so
            // that stepping one is an increment rather than a read back out of the bytes. They
            // are named for the encoding rather than for the field, because this class's own
            // treeHeight is the height of the whole tree - which the loop below reads to decide
            // what is retained - and a local of that name here would hide it silently.
            //
            // The height goes back to 0 for the new leaf rather than being carried over: the loop
            // walks it up, so leaving it where the previous leaf finished would start each leaf
            // at that height.
            int hashTreeHeight = 0;
            int hashTreeIndex = indexLeaf;
            Pack.intToBigEndian(hashTreeHeight, hashTreeAddress, XMSSAddress.TREE_HEIGHT_OFFSET);
            Pack.intToBigEndian(hashTreeIndex, hashTreeAddress, XMSSAddress.TREE_INDEX_OFFSET);
            while (!stack.isEmpty() && stack.peek().getHeight() == node.getHeight())
            {
                /* add to authenticationPath if leafIndex == 1 */
                int indexOnHeight = indexLeaf / (1 << node.getHeight());
                if (indexOnHeight == 1)
                {
                    authenticationPath.add(node);
                }
                /* store next right authentication node */
                if (indexOnHeight == 3 && node.getHeight() < (treeHeight - k))
                {
                    treeHashInstances.get(node.getHeight()).setNode(node);
                }
                if (indexOnHeight >= 3 && (indexOnHeight & 1) == 1 && node.getHeight() >= (treeHeight - k)
                    && node.getHeight() <= (treeHeight - 2))
                {
                    if (retain.get(node.getHeight()) == null)
                    {
                        LinkedList<XMSSNode> queue = new LinkedList<XMSSNode>();
                        queue.add(node);
                        retain.put(node.getHeight(), queue);
                    }
                    else
                    {
                        retain.get(node.getHeight()).add(node);
                    }
                }
                hashTreeIndex = (hashTreeIndex - 1) / 2;
                Pack.intToBigEndian(hashTreeIndex, hashTreeAddress, XMSSAddress.TREE_INDEX_OFFSET);
                node = XMSSNodeUtil.randomizeHash(wotsPlus, stack.pop(), node, hashTreeAddress, nodeKey, nodeMask);
                node = node.incrementHeight();
                Pack.intToBigEndian(++hashTreeHeight, hashTreeAddress, XMSSAddress.TREE_HEIGHT_OFFSET);
            }
            /* push to stack */
            stack.push(node);
        }
        root = stack.pop();
    }

    /**
     * Advance this state one leaf (RFC 8391 sec. 4.1.6 algorithm 11).
     *
     * @param otsAddress the 32-byte encoding of the OTS hash address the tree starts at. Read and
     *                   never written, as in {@link #initialize}: the leaf branch below and the
     *                   tree hash updates that close the method both step a copy of it. Here that
     *                   is the contract rather than a live hazard - nothing reached today reads
     *                   the OTS address word of what it passed afterwards, and dropping the copy
     *                   leaves the compatibility oracle and this package's own tests green - but
     *                   the same starting address is handed in once per leaf a state is walked
     *                   forward over, and the copy is what keeps those calls independent.
     */
    private void nextAuthenticationPath(byte[] publicSeed, byte[] secretSeed, byte[] otsAddress)
    {
        if (used)
        {
            throw new IllegalStateException("index already used");
        }
        if (index > maxIndex - 1)
        {
            throw new IllegalStateException("index out of bounds");
        }
        
        /* determine tau */
        int tau = XMSSUtil.calculateTau(index, treeHeight);
        /* parent of leaf on height tau+1 is a left node */
        if (((index >> (tau + 1)) & 1) == 0 && (tau < (treeHeight - 1)))
        {
            keep.put(tau, authenticationPath.get(tau));
        }

        /* prepare addresses - the two below the leaf's name the same tree as it, so they are taken
         * from its encoding rather than assembled beside it */
        byte[] leafAddress = Arrays.clone(otsAddress);
        byte[] lTreeAddress = XMSSAddress.subtreeAddressOf(otsAddress, XMSSAddress.LTREE_TYPE);
        byte[] hashTreeAddress = XMSSAddress.subtreeAddressOf(otsAddress, XMSSAddress.HASH_TREE_TYPE);
        /* and one pair of working buffers for whichever of the two branches below runs; see
         * XMSSNodeUtil.randomizeHash */
        int n = wotsPlus.getParams().getTreeDigestSize();
        byte[] nodeKey = new byte[n];
        byte[] nodeMask = new byte[2 * n];

        /* leaf is a left node */
        if (tau == 0)
        {
            Pack.intToBigEndian(index, leafAddress, XMSSAddress.OTS_ADDRESS_OFFSET);
            /*
             * import WOTSPlusSecretKey as its needed to calculate the public
             * key on the fly
             */
            wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretSeed, leafAddress), publicSeed);
            WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(leafAddress);
            Pack.intToBigEndian(index, lTreeAddress, XMSSAddress.LTREE_ADDRESS_OFFSET);
            XMSSNode node = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPublicKey, lTreeAddress, nodeKey, nodeMask);
            authenticationPath.set(0, node);
        }
        else
        {
            /* add new left node on height tau to authentication path */
            Pack.intToBigEndian(tau - 1, hashTreeAddress, XMSSAddress.TREE_HEIGHT_OFFSET);
            Pack.intToBigEndian(index >> tau, hashTreeAddress, XMSSAddress.TREE_INDEX_OFFSET);
            // the public seed, and a placeholder where the one-time secret key goes. Nothing on
            // this branch derives a WOTS+ key: randomizeHash below takes getPublicSeed() and
            // getKhf() off this object and reads nothing else, where the leaf branch above imports
            // a real key because it goes on to build a public key out of it. So the PRF this used
            // to run was a hash computed to be thrown away, on the roughly half of all advances
            // that come here - and it was a PRF over an address this branch never named its leaf
            // in, so what it derived was not even the leaf's key. The zero placeholder is the one
            // XMSSEngine imports wherever it needs the seed alone, and it leaves no one-time key
            // material behind in an object that has no use for it.
            wotsPlus.importKeys(new byte[n], publicSeed);
            // the node this state kept the last time the path passed height tau - 1. One that
            // reached this index by signing always has it; one that arrived by import need not, and
            // reading through the gap raises a NullPointerException from inside the hash rather than
            // saying what is wrong.
            XMSSNode keptNode = keep.get(tau - 1);
            if (keptNode == null)
            {
                throw new IllegalStateException("missing keep node in BDS state");
            }
            XMSSNode node = XMSSNodeUtil.randomizeHash(wotsPlus, authenticationPath.get(tau - 1), keptNode,
                hashTreeAddress, nodeKey, nodeMask);
            node = node.incrementHeight();
            authenticationPath.set(tau, node);
            keep.remove(tau - 1);

            /* add new right nodes to authentication path */
            for (int height = 0; height < tau; height++)
            {
                if (height < (treeHeight - k))
                {
                    authenticationPath.set(height, treeHashInstances.get(height).getTailNode());
                }
                else
                {
                    // as for the kept node above: an imported state can be missing the queue for this
                    // height, or carry it empty, and either is a corrupt state rather than a
                    // NullPointerException or a NoSuchElementException from the queue itself
                    List<XMSSNode> retained = retain.get(height);
                    if (retained == null || retained.isEmpty())
                    {
                        throw new IllegalStateException("missing retain node in BDS state");
                    }
                    authenticationPath.set(height, retained.remove(0));
                }
            }

            /* reinitialize treehash instances */
            int minHeight = Math.min(tau, treeHeight - k);
            for (int height = 0; height < minHeight; height++)
            {
                int startIndex = index + 1 + (3 * (1 << height));
                if (startIndex < (1 << treeHeight))
                {
                    treeHashInstances.get(height).initialize(startIndex);
                }
            }
        }
 
        /* update treehash instances */
        for (int i = 0; i < (treeHeight - k) >> 1; i++)
        {
            BDSTreeHash treeHash = getBDSTreeHashInstanceForUpdate();
            if (treeHash != null)
            {
                treeHash.update(stack, wotsPlus, publicSeed, secretSeed, leafAddress);
            }
        }

        index++;
    }

    boolean isUsed()
    {
        return used;
    }

    void markUsed()
    {
        this.used = true;
    }

    private BDSTreeHash getBDSTreeHashInstanceForUpdate()
    {
        BDSTreeHash ret = null;
        for (BDSTreeHash treeHash : treeHashInstances)
        {
            if (treeHash.isFinished() || !treeHash.isInitialized())
            {
                continue;
            }
            if (ret == null)
            {
                ret = treeHash;
                continue;
            }
            if (treeHash.getHeight() < ret.getHeight())
            {
                ret = treeHash;
                continue;
            }
            if (treeHash.getHeight() == ret.getHeight())
            {
                if (treeHash.getIndexLeaf() < ret.getIndexLeaf())
                {
                    ret = treeHash;
                }
            }
        }
        return ret;
    }

    void validate()
    {
        if (authenticationPath == null)
        {
            throw new IllegalStateException("authenticationPath == null");
        }
        if (retain == null)
        {
            throw new IllegalStateException("retain == null");
        }
        if (stack == null)
        {
            throw new IllegalStateException("stack == null");
        }
        if (treeHashInstances == null)
        {
            throw new IllegalStateException("treeHashInstances == null");
        }
        if (keep == null)
        {
            throw new IllegalStateException("keep == null");
        }
        if (treeHeight < 2 || treeHeight > XMSSParameters.MAX_HEIGHT)
        {
            throw new IllegalStateException("treeHeight in BDS state out of bounds");
        }
        if (k > treeHeight || k < 2 || ((treeHeight - k) & 1) != 0)
        {
            throw new IllegalStateException("k in BDS state out of bounds");
        }
        int maxIndexLimit = (1 << treeHeight) - 1;
        if (maxIndex < 0 || maxIndex > maxIndexLimit || index < 0 || index > maxIndex + 1)
        {
            throw new IllegalStateException("index in BDS state out of bounds");
        }
        if (root == null)
        {
            if (!authenticationPath.isEmpty())
            {
                throw new IllegalStateException("authenticationPath present without root");
            }
        }
        else
        {
            if (root.getHeight() != treeHeight || authenticationPath.size() != treeHeight)
            {
                throw new IllegalStateException("inconsistent root or authenticationPath in BDS state");
            }
        }
        if (treeHashInstances.size() != treeHeight - k || retain.size() > k - 1
            || stack.size() > treeHeight || keep.size() > treeHeight)
        {
            throw new IllegalStateException("inconsistent collection size in BDS state");
        }
    }

    public void validate(XMSSParameters params)
    {
        validate();
        if (treeHeight != params.getHeight() || k != params.getK())
        {
            throw new IllegalStateException("BDS state does not match XMSS parameters");
        }

        int digestSize = params.getTreeDigestSize();
        validateNode(root, digestSize, treeHeight, treeHeight);
        for (int i = 0; i < authenticationPath.size(); i++)
        {
            validateRequiredNode(authenticationPath.get(i), digestSize, i, i);
        }

        for (Iterator<Integer> it = retain.keySet().iterator(); it.hasNext();)
        {
            int height = it.next().intValue();
            if (height < treeHeight - k || height > treeHeight - 2)
            {
                throw new IllegalStateException("retain height in BDS state out of bounds");
            }
            List<XMSSNode> nodes = retain.get(height);
            int maximumRetained = (1 << (treeHeight - height - 1)) - 1;
            if (nodes == null || nodes.size() > maximumRetained)
            {
                throw new IllegalStateException("retain queue in BDS state out of bounds");
            }
            validateNodes(nodes, digestSize, height, height);
        }

        validateNodes(stack, digestSize, 0, treeHeight);
        for (int i = 0; i < treeHashInstances.size(); i++)
        {
            BDSTreeHash treeHash = treeHashInstances.get(i);
            if (treeHash == null || treeHash.getInitialHeight() != i || treeHash.getRawHeight() < 0
                || treeHash.getRawHeight() > i || treeHash.getIndexLeaf() < 0
                || treeHash.getIndexLeaf() > (1 << treeHeight) - 1)
            {
                throw new IllegalStateException("tree hash in BDS state out of bounds");
            }
            validateNode(treeHash.getTailNode(), digestSize, 0, i);
        }

        for (Iterator<Integer> it = keep.keySet().iterator(); it.hasNext();)
        {
            int height = it.next().intValue();
            if (height < 0 || height > treeHeight - 2)
            {
                throw new IllegalStateException("keep height in BDS state out of bounds");
            }
            validateRequiredNode(keep.get(height), digestSize, height, height);
        }
    }

    /**
     * Confirm the root this state carries is the one the enclosing private key declares. The two are
     * independent copies of the same value in one encoding and always agree on a genuine key, so a
     * disagreement means the stored key has been corrupted. Left unchecked, a corrupted root is
     * accepted and then poisons every signature the key makes - the root is hashed into the message
     * digest, so the signature simply does not verify, with nothing to say why (github #2414).
     * <p>
     * A null root on either side is not compared: BDS.validate tolerates an absent root node, and a
     * key built without one carries zeros.
     *
     * @param expectedRoot the root the private key declares.
     */
    public void validateRoot(byte[] expectedRoot)
    {
        if (root == null || expectedRoot == null)
        {
            return;
        }

        if (!Arrays.areEqual(root.getValue(), expectedRoot))
        {
            throw new IllegalStateException("BDS state root does not match the private key root");
        }
    }

    public void validate(XMSSParameters params, int expectedIndex)
    {
        validate(params);
        // RFC 8391 Section 1.1 requires each secret-key state to be used only once. Tie restored BDS
        // state to the enclosing private-key index so stale or mismatched traversal state is rejected.
        if (index != expectedIndex)
        {
            throw new IllegalStateException("BDS state has wrong index");
        }
    }

    private static void validateNodes(Iterable<XMSSNode> nodes, int digestSize, int minimumHeight,
        int maximumHeight)
    {
        for (Iterator<XMSSNode> it = nodes.iterator(); it.hasNext();)
        {
            validateRequiredNode(it.next(), digestSize, minimumHeight, maximumHeight);
        }
    }

    private static void validateRequiredNode(XMSSNode node, int digestSize, int minimumHeight,
        int maximumHeight)
    {
        if (node == null)
        {
            throw new IllegalStateException("null XMSS node in BDS state");
        }
        validateNode(node, digestSize, minimumHeight, maximumHeight);
    }

    private static void validateNode(XMSSNode node, int digestSize, int minimumHeight, int maximumHeight)
    {
        if (node != null)
        {
            if (node.getHeight() < minimumHeight || node.getHeight() > maximumHeight
                || !node.hasValueLength(digestSize))
            {
                throw new IllegalStateException("XMSS node in BDS state out of bounds");
            }
        }
    }

    int getTreeHeight()
    {
        return treeHeight;
    }

    XMSSNode getRoot()
    {
        return root;
    }

    /**
     * The authentication path, as a copy: the one accessor here that still makes one, because
     * what XMSSEngine does with it is put it in a signature that outlives the call. The five
     * below hand out the state's own collections, and say there why that is enough for the one
     * caller they have.
     */
    List<XMSSNode> getAuthenticationPath()
    {
        List<XMSSNode> authenticationPath = new ArrayList<XMSSNode>();

        authenticationPath.addAll(this.authenticationPath);
        return authenticationPath;
    }

    /**
     * Whether this state has an authentication path yet, which is what says whether the key
     * holding it can sign: a key decoded from an encoding that carried no traversal state has
     * none. The XMSS^MT side asks the same question of a whole BDSStateMap, which answers it with
     * its own isEmpty().
     * <p>
     * Here rather than {@code getAuthenticationPath().isEmpty()} at the call sites, which built a
     * copy of the path in order to ask its size - once per signature and once per
     * hasTraversalState(). Handing out no path, this needs none of the copying that accessor
     * exists for, so it is a predicate rather than a second way to reach the list.
     * </p>
     */
    boolean isAuthenticationPathEmpty()
    {
        return authenticationPath.isEmpty();
    }

    /**
     * Whether this state, standing on the last leaf of a tree, belongs to the tree at
     * {@code treeAddress} of layer {@code layerAddress} of the key whose seeds are given.
     * <p>
     * The last leaf of a tree is a right node, so the first node of its authentication path is
     * the leaf before it. That leaf is recomputed from the seeds at the address of the tree asked
     * about and compared with the one the state carries: a state from any other tree, or from any
     * other key, holds a different node there. One WOTS+ public key and one L-tree, the cost of a
     * single leaf.
     * </p>
     *
     * @param publicSeed    the public seed of the key holding this state.
     * @param secretKeySeed the secret key seed of the key holding this state.
     * @param layerAddress  the layer of the tree, zero for the bottom layer.
     * @param treeAddress   the tree of that layer; a negative one names no tree.
     * @return true if this state is on the last leaf of that tree, false otherwise.
     */
    boolean isLastLeafOfTree(byte[] publicSeed, byte[] secretKeySeed, int layerAddress, long treeAddress)
    {
        int lastLeaf = (1 << treeHeight) - 1;
        if (treeAddress < 0 || index != lastLeaf || wotsPlus == null || authenticationPath.isEmpty())
        {
            return false;
        }

        // a WOTS+ instance of its own: importKeys() writes into the instance, and this state's
        // is the one its next signature uses
        WOTSPlus checker = new WOTSPlus(wotsPlus.getParams());
        try
        {
            int leaf = lastLeaf - 1;
            byte[] otsAddress = XMSSAddress.otsHashAddress(layerAddress, treeAddress, leaf);
            byte[] lTreeAddress = XMSSAddress.subtreeAddressOf(otsAddress, XMSSAddress.LTREE_TYPE);
            Pack.intToBigEndian(leaf, lTreeAddress, XMSSAddress.LTREE_ADDRESS_OFFSET);

            byte[] wotsPlusSecretKey = checker.getWOTSPlusSecretKey(secretKeySeed, otsAddress);
            checker.importKeys(wotsPlusSecretKey, publicSeed);
            Arrays.clear(wotsPlusSecretKey);
            WOTSPlusPublicKeyParameters wotsPlusPublicKey = checker.getPublicKey(otsAddress);

            int n = checker.getParams().getTreeDigestSize();
            XMSSNode node = XMSSNodeUtil.lTree(checker, wotsPlusPublicKey, lTreeAddress, new byte[n],
                new byte[2 * n]);

            return Arrays.constantTimeAreEqual(node.getValue(), authenticationPath.get(0).getValue());
        }
        finally
        {
            checker.clearSecretKeySeed();
        }
    }

    public int getIndex()
    {
        return index;
    }

    public int getMaxIndex()
    {
        return maxIndex;
    }

    int getK()
    {
        return k;
    }

    /*
     * The state's own five collections, by reference rather than as a copy of each.
     * BDSStateCodec.writeBDS is the caller - it asks each one its size and iterates it, writing
     * every one of them to a stream and none of them to itself, the terms XMSSReducedSignature
     * hands out its WOTS+ blocks on.
     *
     * What a copy would guard against is a caller that writes, not the state writing to itself.
     * These five are filled inside constructors and never after: advancing means building the
     * successor (getNextState, and BDSStateMap.getNextState over it), and initialize() and
     * nextAuthenticationPath() are both private and reached only from a constructor, over
     * collections it has already copied. The one thing a published state does change in place is
     * its used mark, which markUsed() sets and writeBDS reads through isUsed() rather than through
     * any of these.
     *
     * So a reader that writes nothing has nothing to be protected from, and the copies these
     * replace cost an h = 10 SHA-256 XMSS key 896 of the 5664 bytes it allocated per getEncoded(),
     * and an h = 20 d = 2 XMSS^MT key 857 of 5825 - most of it the eight tree hash instances
     * cloneTreeHashInstances() walks, at 368 bytes, and the 184 a stack and a keep map that are
     * both empty at index 0 were costing to copy.
     *
     * getAuthenticationPath() above is the copying accessor that stays, because the path it hands
     * XMSSEngine goes into a signature that outlives the call, where these are read and dropped
     * inside writeBDS. The other four had no caller left but the tests and are gone; anything that
     * needs one of them to hold still wants the copy BDS(BDS) makes rather than one of its own,
     * because the depth is not obvious - cloneRetain() reaches the queues nextAuthenticationPath()
     * calls remove(0) on, and cloneTreeHashInstances() each instance it updates, where copying the
     * map or the list alone would leave both shared. The field by field constructor is not that
     * copy: it adopts what it is handed, for the decoder that built it.
     */

    List<XMSSNode> getLiveAuthenticationPath()
    {
        return authenticationPath;
    }

    Map<Integer, List<XMSSNode>> getLiveRetain()
    {
        return retain;
    }

    Stack<XMSSNode> getLiveStack()
    {
        return stack;
    }

    List<BDSTreeHash> getLiveTreeHashInstances()
    {
        return treeHashInstances;
    }

    Map<Integer, XMSSNode> getLiveKeep()
    {
        return keep;
    }

    public BDS withWOTSDigest(ASN1ObjectIdentifier digestName)
    {
        return new BDS(this, digestName, -1);
    }

    public BDS withWOTSDigest(ASN1ObjectIdentifier digestName, int digestSize)
    {
        return new BDS(this, digestName, digestSize);
    }

    public BDS withMaxIndex(int maxIndex, ASN1ObjectIdentifier digestName)
    {
        return new BDS(this, maxIndex, digestName, -1);
    }

    public BDS withMaxIndex(int maxIndex, ASN1ObjectIdentifier digestName, int digestSize)
    {
        return new BDS(this, maxIndex, digestName, digestSize);
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        // Java deserialization does not run field initializers, so a crafted stream that declares
        // no fields leaves every collection this state is made of null, and one that declares them
        // can put nulls inside them. The import path rebuilds a state around the digest its key
        // names before anything validates it - withWOTSDigest() clones all five collections - so
        // the matching checks in validate() are reached too late to be what rejects this. Refuse it
        // here, where the stream enters. The nodes those collections hold are validate()'s to check:
        // it is reached with them, and it reports a null one rather than dereferencing it.
        if (authenticationPath == null || retain == null || stack == null
            || treeHashInstances == null || keep == null)
        {
            throw new IOException("incomplete BDS state");
        }
        for (Iterator<Integer> it = retain.keySet().iterator(); it.hasNext();)
        {
            Integer height = it.next();

            // a null key is not merely absent state: TreeMap.get(null) throws in its own right
            if (height == null || retain.get(height) == null)
            {
                throw new IOException("incomplete BDS state");
            }
        }
        for (Iterator<Integer> it = keep.keySet().iterator(); it.hasNext();)
        {
            Integer height = it.next();

            // as with retain above: a null key is not merely absent state, TreeMap.get(null) throws
            if (height == null || keep.get(height) == null)
            {
                throw new IOException("incomplete BDS state");
            }
        }
        for (Iterator<BDSTreeHash> it = treeHashInstances.iterator(); it.hasNext();)
        {
            if (it.next() == null)
            {
                throw new IOException("incomplete BDS state");
            }
        }

        // as in BDSStateMap.readObject(): ObjectInputStream.available() is an estimate of what can
        // be read without blocking rather than an end of data test, and taking a state that does
        // carry a maximum index for one that does not would widen a key shard back to the whole
        // range of the key it came from. read() returns -1 only at the end of this object's data.
        int first = in.read();

        if (first < 0)
        {
            // written before the maximum index was recorded: a BDS knows its own tree height, so
            // it can resolve that here rather than having to mark it for someone else to resolve
            this.maxIndex = (1 << treeHeight) - 1;
        }
        else
        {
            byte[] encoded = new byte[4];

            encoded[0] = (byte)first;
            in.readFully(encoded, 1, encoded.length - 1);

            this.maxIndex = Pack.bigEndianToInt(encoded, 0);
        }
        if (maxIndex > ((1 << treeHeight) - 1) || index > (maxIndex + 1) || in.read() >= 0)
        {
            throw new IOException("inconsistent BDS data detected");
        }
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeInt(this.maxIndex);
    }
}
