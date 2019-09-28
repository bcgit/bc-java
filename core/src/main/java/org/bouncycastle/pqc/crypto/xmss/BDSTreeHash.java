package org.bouncycastle.pqc.crypto.xmss;

import java.io.Serializable;
import java.util.Stack;


class BDSTreeHash
    implements Serializable, Cloneable
{
    private static final long serialVersionUID = 1L;

    private XMSSNode tailNode;
    private final int initialHeight;
    private int height;
    private int nextIndex;
    private boolean initialized;
    private boolean finished;

    BDSTreeHash(int initialHeight)
    {
        super();
        this.initialHeight = initialHeight;
        initialized = false;
        finished = false;
    }

    void initialize(int nextIndex)
    {
        tailNode = null;
        height = initialHeight;
        this.nextIndex = nextIndex;
        initialized = true;
        finished = false;
    }

    void update(Stack<XMSSNode> stack, WOTSPlus wotsPlus, byte[] publicSeed, byte[] secretSeed, OTSHashAddress otsHashAddress)
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
        otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .withOTSAddress(nextIndex).withChainAddress(otsHashAddress.getChainAddress())
            .withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())
            .build();
        LTreeAddress lTreeAddress = (LTreeAddress)new LTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .withLTreeAddress(nextIndex).build();
        HashTreeAddress hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .withTreeIndex(nextIndex).build();
            /* calculate leaf node */
        wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretSeed, otsHashAddress), publicSeed);
        WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(otsHashAddress);
        XMSSNode node = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPublicKey, lTreeAddress);

        while (!stack.isEmpty() && stack.peek().getHeight() == node.getHeight()
            && stack.peek().getHeight() != initialHeight)
        {
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

        if (tailNode == null)
        {
            tailNode = node;
        }
        else
        {
            if (tailNode.getHeight() == node.getHeight())
            {
                hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
                    .withLayerAddress(hashTreeAddress.getLayerAddress())
                    .withTreeAddress(hashTreeAddress.getTreeAddress())
                    .withTreeHeight(hashTreeAddress.getTreeHeight())
                    .withTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2)
                    .withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
                node = XMSSNodeUtil.randomizeHash(wotsPlus, tailNode, node, hashTreeAddress);
                node = new XMSSNode(tailNode.getHeight() + 1, node.getValue());
                tailNode = node;
                hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
                    .withLayerAddress(hashTreeAddress.getLayerAddress())
                    .withTreeAddress(hashTreeAddress.getTreeAddress())
                    .withTreeHeight(hashTreeAddress.getTreeHeight() + 1)
                    .withTreeIndex(hashTreeAddress.getTreeIndex())
                    .withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
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

    int getHeight()
    {
        if (!initialized || finished)
        {
            return Integer.MAX_VALUE;
        }
        return height;
    }

    int getIndexLeaf()
    {
        return nextIndex;
    }

    void setNode(XMSSNode node)
    {
        tailNode = node;
        height = node.getHeight();
        if (height == initialHeight)
        {
            finished = true;
        }
    }

    boolean isFinished()
    {
        return finished;
    }

    boolean isInitialized()
    {
        return initialized;
    }

    public XMSSNode getTailNode()
    {
        return tailNode;
    }

    protected BDSTreeHash clone()
    {
        BDSTreeHash th = new BDSTreeHash(this.initialHeight);

        th.tailNode = this.tailNode;
        th.height = this.height;
        th.nextIndex = this.nextIndex;
        th.initialized = this.initialized;
        th.finished = this.finished;

        return th;
    }
}

