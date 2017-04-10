package org.bouncycastle.pqc.crypto.xmss;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import java.util.TreeMap;

/**
 * BDS.
 *
 */
public class BDS
    implements Serializable
{

    private static final long serialVersionUID = 1L;

    private class TreeHash
        implements Serializable
    {

        private static final long serialVersionUID = 1L;

        private XMSSNode tailNode;
        private final int initialHeight;
        private int height;
        private int nextIndex;
        private boolean initialized;
        private boolean finished;

        private TreeHash(int initialHeight)
        {
            super();
            this.initialHeight = initialHeight;
            initialized = false;
            finished = false;
        }

        private void initialize(int nextIndex)
        {
            tailNode = null;
            height = initialHeight;
            this.nextIndex = nextIndex;
            initialized = true;
            finished = false;
        }

        private void update(OTSHashAddress otsHashAddress)
        {
            if (otsHashAddress == null)
            {
                throw new NullPointerException("otsHashAddress == null");
            }
            if (finished || !initialized)
            {
                throw new IllegalStateException("finished or not initialized");
            }
            /* prepare addresses */
            otsHashAddress.setOTSAddress(nextIndex);
            LTreeAddress lTreeAddress = new LTreeAddress();
            lTreeAddress.setLayerAddress(otsHashAddress.getLayerAddress());
            lTreeAddress.setTreeAddress(otsHashAddress.getTreeAddress());
            lTreeAddress.setLTreeAddress(nextIndex);
            HashTreeAddress hashTreeAddress = new HashTreeAddress();
            hashTreeAddress.setLayerAddress(otsHashAddress.getLayerAddress());
            hashTreeAddress.setTreeAddress(otsHashAddress.getTreeAddress());
            hashTreeAddress.setTreeHeight(0);
            hashTreeAddress.setTreeIndex(nextIndex);
			
			/* calculate leaf node */
            wotsPlus.importKeys(xmss.getWOTSPlusSecretKey(otsHashAddress), xmss.getPublicSeed());
            WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(otsHashAddress);
            XMSSNode node = xmss.lTree(wotsPlusPublicKey, lTreeAddress);

            while (!stack.isEmpty() && stack.peek().getHeight() == node.getHeight() && stack.peek().getHeight() != initialHeight)
            {
                hashTreeAddress.setTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2);
                node = xmss.randomizeHash(stack.pop(), node, hashTreeAddress);
                node.setHeight(node.getHeight() + 1);
                hashTreeAddress.setTreeHeight(hashTreeAddress.getTreeHeight() + 1);
            }

            if (tailNode == null)
            {
                tailNode = node;
            }
            else
            {
                if (tailNode.getHeight() == node.getHeight())
                {
                    hashTreeAddress.setTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2);
                    node = xmss.randomizeHash(tailNode, node, hashTreeAddress);
                    node.setHeight(tailNode.getHeight() + 1);
                    tailNode = node;
                    hashTreeAddress.setTreeHeight(hashTreeAddress.getTreeHeight() + 1);
                }
                else
                {
                    stack.push(node);
                }
            }

            if (tailNode.getHeight() == initialHeight)
            {
                finished = true;
            }
            else
            {
                height = node.getHeight();
                nextIndex++;
            }
        }

        private int getHeight()
        {
            if (!initialized || finished)
            {
                return Integer.MAX_VALUE;
            }
            return height;
        }

        private int getIndexLeaf()
        {
            return nextIndex;
        }

        private void setNode(XMSSNode node)
        {
            tailNode = node;
            height = node.getHeight();
            if (height == initialHeight)
            {
                finished = true;
            }
        }

        private boolean isFinished()
        {
            return finished;
        }

        private boolean isInitialized()
        {
            return initialized;
        }
    }

    private transient XMSS xmss;
    private transient WOTSPlus wotsPlus;
    private final int treeHeight;
    private int k;
    private XMSSNode root;
    private List<XMSSNode> authenticationPath;
    private Map<Integer, Stack<XMSSNode>> retain;
    private Stack<XMSSNode> stack;
    private List<TreeHash> treeHashInstances;
    private Map<Integer, XMSSNode> keep;
    private int index;

    protected BDS(XMSS xmss)
    {
        super();
        if (xmss == null)
        {
            throw new NullPointerException("xmss == null");
        }
        this.xmss = xmss;
        wotsPlus = xmss.getWOTSPlus();
        treeHeight = xmss.getParams().getHeight();
        k = xmss.getParams().getK();
        if (k > treeHeight || k < 2 || ((treeHeight - k) % 2) != 0)
        {
            throw new IllegalArgumentException("illegal value for BDS parameter k");
        }
        authenticationPath = new ArrayList<XMSSNode>();
        retain = new TreeMap<Integer, Stack<XMSSNode>>();
        stack = new Stack<XMSSNode>();
        initializeTreeHashInstances();
        keep = new TreeMap<Integer, XMSSNode>();
        index = 0;
    }

    private void initializeTreeHashInstances()
    {
        treeHashInstances = new ArrayList<TreeHash>();
        for (int height = 0; height < (treeHeight - k); height++)
        {
            treeHashInstances.add(new TreeHash(height));
        }
    }

    protected XMSSNode initialize(OTSHashAddress otsHashAddress)
    {
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }
		/* prepare addresses */
        LTreeAddress lTreeAddress = new LTreeAddress();
        lTreeAddress.setLayerAddress(otsHashAddress.getLayerAddress());
        lTreeAddress.setTreeAddress(otsHashAddress.getTreeAddress());
        HashTreeAddress hashTreeAddress = new HashTreeAddress();
        hashTreeAddress.setLayerAddress(otsHashAddress.getLayerAddress());
        hashTreeAddress.setTreeAddress(otsHashAddress.getTreeAddress());
		
		/* iterate indexes */
        for (int indexLeaf = 0; indexLeaf < (1 << treeHeight); indexLeaf++)
        {
			/* generate leaf */
            otsHashAddress.setOTSAddress(indexLeaf);
			/* import WOTSPlusSecretKey as its needed to calculate the public key on the fly */
            wotsPlus.importKeys(xmss.getWOTSPlusSecretKey(otsHashAddress), xmss.getPublicSeed());
            WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(otsHashAddress);
            lTreeAddress.setLTreeAddress(indexLeaf);
            XMSSNode node = xmss.lTree(wotsPlusPublicKey, lTreeAddress);

            hashTreeAddress.setTreeHeight(0);
            hashTreeAddress.setTreeIndex(indexLeaf);
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
                if (indexOnHeight >= 3 && (indexOnHeight & 1) == 1 && node.getHeight() >= (treeHeight - k) && node.getHeight() <= (treeHeight - 2))
                {
                    if (retain.get(node.getHeight()) == null)
                    {
                        Stack<XMSSNode> queue = new Stack<XMSSNode>();
                        queue.add(node.clone());
                        retain.put(node.getHeight(), queue);
                    }
                    else
                    {
                        retain.get(node.getHeight()).add(node.clone());
                    }
                }
                hashTreeAddress.setTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2);
                node = xmss.randomizeHash(stack.pop(), node, hashTreeAddress);
                node.setHeight(node.getHeight() + 1);
                hashTreeAddress.setTreeHeight(hashTreeAddress.getTreeHeight() + 1);
            }
			/* push to stack */
            stack.push(node);
        }
        root = stack.pop();
        return root.clone();
    }

    void nextAuthenticationPath(OTSHashAddress otsHashAddress)
    {
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }
        if (index > ((1 << treeHeight) - 2))
        {
            throw new IllegalStateException("index out of bounds");
        }
		/* prepare addresses */
        LTreeAddress lTreeAddress = new LTreeAddress();
        lTreeAddress.setLayerAddress(otsHashAddress.getLayerAddress());
        lTreeAddress.setTreeAddress(otsHashAddress.getTreeAddress());
        HashTreeAddress hashTreeAddress = new HashTreeAddress();
        hashTreeAddress.setLayerAddress(otsHashAddress.getLayerAddress());
        hashTreeAddress.setTreeAddress(otsHashAddress.getTreeAddress());
		
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
            otsHashAddress.setOTSAddress(index);
			/* import WOTSPlusSecretKey as its needed to calculate the public key on the fly */
            wotsPlus.importKeys(xmss.getWOTSPlusSecretKey(otsHashAddress), xmss.getPublicSeed());
            WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(otsHashAddress);
            lTreeAddress.setLTreeAddress(index);
            XMSSNode node = xmss.lTree(wotsPlusPublicKey, lTreeAddress);
            authenticationPath.set(0, node);
        }
        else
        {
			/* add new left node on height tau to authentication path */
            hashTreeAddress.setTreeHeight(tau - 1);
            hashTreeAddress.setTreeIndex(index >> tau);
            XMSSNode node = xmss.randomizeHash(authenticationPath.get(tau - 1), keep.get(tau - 1), hashTreeAddress);
            node.setHeight(node.getHeight() + 1);
            authenticationPath.set(tau, node);
            keep.remove(tau - 1);
			
			/* add new right nodes to authentication path */
            for (int height = 0; height < tau; height++)
            {
                if (height < (treeHeight - k))
                {
                    authenticationPath.set(height, treeHashInstances.get(height).tailNode.clone());
                }
                else
                {
                    authenticationPath.set(height, retain.get(height).pop());
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
            TreeHash treeHash = getTreeHashInstanceForUpdate();
            if (treeHash != null)
            {
                treeHash.update(otsHashAddress);
            }
        }
        index++;
    }

    private TreeHash getTreeHashInstanceForUpdate()
    {
        TreeHash ret = null;
        for (TreeHash treeHash : treeHashInstances)
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

    protected void validate(boolean isStateForRootTree)
    {
        if (treeHeight != xmss.getParams().getHeight())
        {
            throw new IllegalStateException("wrong height");
        }
        if (isStateForRootTree)
        {
            if (!XMSSUtil.compareByteArray(root.getValue(), xmss.getRoot()))
            {
                throw new IllegalStateException("root in BDS state does not match root of public / private key");
            }
        }
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

    protected void setXMSS(XMSS xmss)
    {
        this.xmss = xmss;
        this.wotsPlus = xmss.getWOTSPlus();
    }

    protected int getIndex()
    {
        return index;
    }
}
