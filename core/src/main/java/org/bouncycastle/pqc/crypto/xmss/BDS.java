package org.bouncycastle.pqc.crypto.xmss;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import java.util.TreeMap;

/**
 * BDS.
 */
public final class BDS
    implements Serializable
{
    private static final long serialVersionUID = 1L;
    
    private transient WOTSPlus wotsPlus;

    private final int treeHeight;
    private final List<BDSTreeHash> treeHashInstances;
    private int k;
    private XMSSNode root;
    private List<XMSSNode> authenticationPath;
    private Map<Integer, LinkedList<XMSSNode>> retain;
    private Stack<XMSSNode> stack;

    private Map<Integer, XMSSNode> keep;
    private int index;
    private boolean used;

    /**
     * Place holder BDS for when state is exhausted.
     *
     * @param params tree parameters
     * @param index the index that has been reached.
     */
    BDS(XMSSParameters params, int index)
    {
        this(params.getWOTSPlus(), params.getHeight(), params.getK());
        this.index = index;
        this.used = true;
    }

    /**
     * Set up constructor.
     *
     * @param params tree parameters
     * @param publicSeed public seed for tree
     * @param secretKeySeed secret seed for tree
     * @param otsHashAddress hash address
     */
    BDS(XMSSParameters params, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress)
    {
        this(params.getWOTSPlus(), params.getHeight(), params.getK());
        this.initialize(publicSeed, secretKeySeed, otsHashAddress);
    }

    /**
     * Set up constructor for a tree where the original BDS state was lost.
     *
     * @param params tree parameters
     * @param publicSeed public seed for tree
     * @param secretKeySeed secret seed for tree
     * @param otsHashAddress hash address
     * @param index index counter for the state to be at.
     */
    BDS(XMSSParameters params, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress, int index)
    {
        this(params.getWOTSPlus(), params.getHeight(), params.getK());

        this.initialize(publicSeed, secretKeySeed, otsHashAddress);

        while (this.index < index)
        {
            this.nextAuthenticationPath(publicSeed, secretKeySeed, otsHashAddress);
            this.used = false;
        }
    }

    private BDS(WOTSPlus wotsPlus, int treeHeight, int k)
    {
        this.wotsPlus = wotsPlus;
        this.treeHeight = treeHeight;
        this.k = k;
        if (k > treeHeight || k < 2 || ((treeHeight - k) % 2) != 0)
        {
            throw new IllegalArgumentException("illegal value for BDS parameter k");
        }
        authenticationPath = new ArrayList<XMSSNode>();
        retain = new TreeMap<Integer, LinkedList<XMSSNode>>();
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

    private BDS(BDS last, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress)
    {
        this.wotsPlus = last.wotsPlus;
        this.treeHeight = last.treeHeight;
        this.k = last.k;
        this.root = last.root;
        this.authenticationPath = new ArrayList<XMSSNode>(last.authenticationPath);
        this.retain = last.retain;
        this.stack = (Stack<XMSSNode>)last.stack.clone();
        this.treeHashInstances = last.treeHashInstances;
        this.keep = new TreeMap<Integer, XMSSNode>(last.keep);
        this.index = last.index;

        this.nextAuthenticationPath(publicSeed, secretKeySeed, otsHashAddress);

        last.used = true;
    }
    
    public BDS getNextState(byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress)
    {
        return new BDS(this, publicSeed, secretKeySeed, otsHashAddress);
    }

    private void initialize(byte[] publicSeed, byte[] secretSeed, OTSHashAddress otsHashAddress)
    {
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }
        /* prepare addresses */
        LTreeAddress lTreeAddress = (LTreeAddress)new LTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .build();
        HashTreeAddress hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .build();

		/* iterate indexes */
        for (int indexLeaf = 0; indexLeaf < (1 << treeHeight); indexLeaf++)
        {
			/* generate leaf */
            otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder()
                .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                .withOTSAddress(indexLeaf).withChainAddress(otsHashAddress.getChainAddress())
                .withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())
                .build();
			/*
			 * import WOTSPlusSecretKey as its needed to calculate the public
			 * key on the fly
			 */
            wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretSeed, otsHashAddress), publicSeed);
            WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(otsHashAddress);
            lTreeAddress = (LTreeAddress)new LTreeAddress.Builder().withLayerAddress(lTreeAddress.getLayerAddress())
                .withTreeAddress(lTreeAddress.getTreeAddress()).withLTreeAddress(indexLeaf)
                .withTreeHeight(lTreeAddress.getTreeHeight()).withTreeIndex(lTreeAddress.getTreeIndex())
                .withKeyAndMask(lTreeAddress.getKeyAndMask()).build();
            XMSSNode node = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPublicKey, lTreeAddress);

            hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
                .withLayerAddress(hashTreeAddress.getLayerAddress())
                .withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeIndex(indexLeaf)
                .withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
            while (!stack.isEmpty() && stack.peek().getHeight() == node.getHeight())
            {
				/* add to authenticationPath if leafIndex == 1 */
                int indexOnHeight = ((int)Math.floor(indexLeaf / (1 << node.getHeight())));
                if (indexOnHeight == 1)
                {
                    authenticationPath.add(node.clone());
                }
				/* store next right authentication node */
                if (indexOnHeight == 3 && node.getHeight() < (treeHeight - k))
                {
                    treeHashInstances.get(node.getHeight()).setNode(node.clone());
                }
                if (indexOnHeight >= 3 && (indexOnHeight & 1) == 1 && node.getHeight() >= (treeHeight - k)
                    && node.getHeight() <= (treeHeight - 2))
                {
                    if (retain.get(node.getHeight()) == null)
                    {
                        LinkedList<XMSSNode> queue = new LinkedList<XMSSNode>();
                        queue.add(node.clone());
                        retain.put(node.getHeight(), queue);
                    }
                    else
                    {
                        retain.get(node.getHeight()).add(node.clone());
                    }
                }
                hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
                    .withLayerAddress(hashTreeAddress.getLayerAddress())
                    .withTreeAddress(hashTreeAddress.getTreeAddress())
                    .withTreeHeight(hashTreeAddress.getTreeHeight())
                    .withTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2)
                    .withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
                node = XMSSNodeUtil.randomizeHash(wotsPlus, stack.pop(), node, hashTreeAddress);
                node = new XMSSNode(node.getHeight() + 1, node.getValue());
                hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
                    .withLayerAddress(hashTreeAddress.getLayerAddress())
                    .withTreeAddress(hashTreeAddress.getTreeAddress())
                    .withTreeHeight(hashTreeAddress.getTreeHeight() + 1)
                    .withTreeIndex(hashTreeAddress.getTreeIndex()).withKeyAndMask(hashTreeAddress.getKeyAndMask())
                    .build();
            }
			/* push to stack */
            stack.push(node);
        }
        root = stack.pop();
    }

    private void nextAuthenticationPath(byte[] publicSeed, byte[] secretSeed, OTSHashAddress otsHashAddress)
    {
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }
        if (used)
        {
            throw new IllegalStateException("index already used");
        }
        if (index > ((1 << treeHeight) - 2))
        {
            throw new IllegalStateException("index out of bounds");
        }
		/* prepare addresses */
        LTreeAddress lTreeAddress = (LTreeAddress)new LTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .build();
        HashTreeAddress hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .build();

		/* determine tau */
        int tau = XMSSUtil.calculateTau(index, treeHeight);
    	/* parent of leaf on height tau+1 is a left node */
        if (((index >> (tau + 1)) & 1) == 0 && (tau < (treeHeight - 1)))
        {
            keep.put(tau, authenticationPath.get(tau).clone());
        }
		/* leaf is a left node */
        if (tau == 0)
        {
            otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder()
                .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                .withOTSAddress(index).withChainAddress(otsHashAddress.getChainAddress())
                .withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())
                .build();
			/*
			 * import WOTSPlusSecretKey as its needed to calculate the public
			 * key on the fly
			 */
            wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretSeed, otsHashAddress), publicSeed);
            WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(otsHashAddress);
            lTreeAddress = (LTreeAddress)new LTreeAddress.Builder().withLayerAddress(lTreeAddress.getLayerAddress())
                .withTreeAddress(lTreeAddress.getTreeAddress()).withLTreeAddress(index)
                .withTreeHeight(lTreeAddress.getTreeHeight()).withTreeIndex(lTreeAddress.getTreeIndex())
                .withKeyAndMask(lTreeAddress.getKeyAndMask()).build();
            XMSSNode node = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPublicKey, lTreeAddress);
            authenticationPath.set(0, node);
        }
        else
        {
			/* add new left node on height tau to authentication path */
            hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
                .withLayerAddress(hashTreeAddress.getLayerAddress())
                .withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(tau - 1)
                .withTreeIndex(index >> tau).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
            XMSSNode node = XMSSNodeUtil.randomizeHash(wotsPlus, authenticationPath.get(tau - 1), keep.get(tau - 1), hashTreeAddress);
            node = new XMSSNode(node.getHeight() + 1, node.getValue());
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
                    authenticationPath.set(height, retain.get(height).removeFirst());
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
                treeHash.update(stack, wotsPlus, publicSeed, secretSeed, otsHashAddress);
            }
        }

        index++;
    }

    boolean isUsed()
    {
        return used;
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

    protected void validate()
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
        if (!XMSSUtil.isIndexValid(treeHeight, index))
        {
            throw new IllegalStateException("index in BDS state out of bounds");
        }
    }

    protected int getTreeHeight()
    {
        return treeHeight;
    }

    protected XMSSNode getRoot()
    {
        return root.clone();
    }

    protected List<XMSSNode> getAuthenticationPath()
    {
        List<XMSSNode> authenticationPath = new ArrayList<XMSSNode>();
        for (XMSSNode node : this.authenticationPath)
        {
            authenticationPath.add(node.clone());
        }
        return authenticationPath;
    }

    protected void setXMSS(XMSSParameters xmss)
    {
        if (treeHeight != xmss.getHeight())
        {
            throw new IllegalStateException("wrong height");
        }

        this.wotsPlus = xmss.getWOTSPlus();
    }

    protected int getIndex()
    {
        return index;
    }
}
