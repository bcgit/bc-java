package org.bouncycastle.pqc.crypto.picnic;


import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;


class Tree
{

    private static final int MAX_SEED_SIZE_BYTES = 32;
//    private final int MAX_AUX_BYTES;


    private int depth;       /* The depth of the tree */
    byte[][] nodes;  /* The data for each node */
    private int dataSize;    /* The size data at each node, in bytes */
    private boolean[] haveNode; /* If we have the data (seed or hash) for node i, haveSeed[i] is 1 */
    private boolean[] exists;   /* Since the tree is not always complete, nodes marked 0 don't exist */
    private int numNodes;    /* The total number of nodes in the tree */
    private int numLeaves;   /* The total number of leaves in the tree */

    private PicnicEngine engine;

    protected byte[][] getLeaves()
    {
        return this.nodes;
    }
    protected int getLeavesOffset()
    {
        return this.numNodes - this.numLeaves;
    }

    public Tree(PicnicEngine engine, int numLeaves, int dataSize)
    {
        this.engine = engine;
//        MAX_AUX_BYTES = ((PicnicEngine.LOWMC_MAX_AND_GATES + PicnicEngine.LOWMC_MAX_KEY_BITS) / 8 + 1);
        
        this.depth =  Utils.ceil_log2(numLeaves) + 1;
        this.numNodes = ((1 << (this.depth)) - 1) - ((1 << (this.depth - 1)) - numLeaves);  /* Num nodes in complete - number of missing leaves */
        this.numLeaves = numLeaves;
        this.dataSize = dataSize;
        this.nodes =  new byte[this.numNodes][dataSize];

        for (int i = 0; i < this.numNodes; i++)
        {
            this.nodes[i] = new byte[dataSize];
        }
    
        this.haveNode = new boolean[this.numNodes];
        /* Depending on the number of leaves, the tree may not be complete */
        this.exists = new boolean[this.numNodes];

        /* Set leaves */
        Arrays.fill(this.exists, this.numNodes - this.numLeaves, this.numNodes, true);
        for (int i = this.numNodes - this.numLeaves; i > 0; i--)
        {
            if (exists(2 * i + 1) || exists(2 * i + 2) )
            {
                this.exists[i] = true;
            }
        }
        this.exists[0] = true;
    }

    /* Create a Merkle tree by hashing up all nodes.
     * leafData must have length this.numNodes, but some may be NULL. */
    protected void buildMerkleTree(byte[][] leafData, byte[] salt)
    {
        int firstLeaf = this.numNodes - this.numLeaves;

        /* Copy data to the leaves. The actual data being committed to has already been
         * hashed, according to the spec. */
        for (int i = 0; i < this.numLeaves; i++)
        {
            if (leafData[i] != null)
            {
                System.arraycopy(leafData[i], 0, this.nodes[firstLeaf + i], 0, this.dataSize);
                this.haveNode[firstLeaf + i] = true;
            }
        }
        /* Starting at the leaves, work up the tree, computing the hashes for intermediate nodes */
        for (int i = this.numNodes; i > 0; i--)
        {
            computeParentHash(i, salt);
        }
    }

    /* verifyMerkleTree: verify for each leaf that is set */
    protected int verifyMerkleTree(byte[][] leafData, byte[] salt)
    {
        int firstLeaf = this.numNodes - this.numLeaves;

        /* Copy the leaf data, where we have it. The actual data being committed to has already been
         * hashed, according to the spec. */
        for (int i = 0; i < this.numLeaves; i++)
        {
            if (leafData[i] != null)
            {
                if (this.haveNode[firstLeaf + i])
                {
                    return -1;  /* A leaf was assigned from the prover for a node we've recomputed */
                }

                if (leafData[i] != null)
                {
                    System.arraycopy(leafData[i], 0, this.nodes[firstLeaf + i], 0, this.dataSize);
                    this.haveNode[firstLeaf + i] = true;
                }
            }
        }

        /* At this point the tree has some of the leaves, and some intermediate nodes
         * Work up the tree, computing all nodes we don't have that are missing. */
        for (int i = this.numNodes; i > 0; i--)
        {
            computeParentHash(i, salt);
        }

        /* Fail if the root was not computed. */
        if (!this.haveNode[0])
        {
            return -1;
        }
        return 0;
    }

    protected int reconstructSeeds(int[] hideList, int hideListSize,
                         byte[] input, int inputLen, byte[] salt, int repIndex)
    {
        int ret =  0;

//        if (inputLen > INT_MAX) {
//            return -1;
//        }

        int inLen = inputLen;

        int[] revealedSize = new int[1];
        revealedSize[0] = 0;
        int[] revealed = this.getRevealedNodes(hideList, hideListSize, revealedSize);
        for (int i = 0; i < revealedSize[0]; i++)
        {
            inLen -= engine.seedSizeBytes;
            if (inLen < 0)
            {
                return -1;
            }
            System.arraycopy(input, i*engine.seedSizeBytes, this.nodes[revealed[i]], 0, engine.seedSizeBytes);
            this.haveNode[revealed[i]] = true;
        }

        expandSeeds(salt, repIndex);

        return ret;
    }

    /* Serialze the missing nodes that the verifier will require to check commitments for non-missing leaves */
    protected byte[] openMerkleTree(int[] missingLeaves, int missingLeavesSize, int[] outputSizeBytes)
    {
        int[] revealedSize = new int[1];
        int[] revealed = this.getRevealedMerkleNodes(missingLeaves, missingLeavesSize, revealedSize);

        /* Serialize output */
        outputSizeBytes[0] = revealedSize[0] * this.dataSize;
        byte[] output = new byte[outputSizeBytes[0]];
        byte[] outputBase = output;

        for (int i = 0; i < revealedSize[0]; i++)
        {
            System.arraycopy(this.nodes[revealed[i]], 0, output, i * this.dataSize, this.dataSize);
        }

        return outputBase;
    }

    /* Returns the number of bytes written to output */
    private int[] getRevealedNodes(int[] hideList, int hideListSize, int[] outputSize)
    {
        /* Compute paths up from hideList to root, store as sets of nodes */
        int pathLen = this.depth - 1;
    
        /* pathSets[i][0...hideListSize] stores the nodes in the path at depth i
         * for each of the leaf nodes in hideListSize */
        int[][] pathSets = new int[pathLen][hideListSize];

        /* Compute the paths back to the root */
        for (int i = 0; i < hideListSize; i++)
        {
            int pos = 0;
            int node = hideList[i] + (this.numNodes - this.numLeaves); /* input lists leaf indexes, translate to nodes */
            pathSets[pos][i] = node;
            pos++;
            while ( (node = getParent(node)) != 0 )
            {
                pathSets[pos][i] = node;
                pos++;
            }
        }
    
        /* Determine seeds to reveal */
        int[] revealed = new int[this.numLeaves];
        int revealedPos = 0;
        for (int d = 0; d < pathLen; d++)
        {
            for (int i = 0; i < hideListSize; i++)
            {
                if (!hasSibling(pathSets[d][i]))
                {
                    continue;
                }
                int sibling =  getSibling(pathSets[d][i]);
                if (!contains(pathSets[d], hideListSize, sibling ))
                {
                    // Determine the seed to reveal 
                    while(!hasRightChild(sibling) && !isLeafNode(sibling))
                    {
                        sibling = 2 * sibling + 1; // sibling = leftChild(sibling)
                    }
    
                    // Only reveal if we haven't already 
                    if (!contains(revealed, revealedPos, sibling))
                    {
                        revealed[revealedPos] = sibling;
                        revealedPos++;
                    }
                }
            }
        }
    
//        free(pathSets[0]);
//        free(pathSets);
    
        outputSize[0] = revealedPos;
        return revealed;
    }

    private int getSibling(int node)
    {
//        assert(node < this.numNodes);
//        assert(node != 0);
//        assert(hasSibling(tree, node));

        if (isLeftChild(node))
        {
            if (node + 1 < this.numNodes)
            {
                return node + 1;
            }
            else
            {
                return 0;
            }
        }
        else
        {
            return node - 1;
        }
    }

    private boolean isLeafNode(int node)
    {
        return (2 * node + 1 >= this.numNodes);
    }


    private boolean hasSibling(int node)
    {
        if (!exists(node))
        {
            return false;
        }

        if (isLeftChild(node) && !exists(node + 1))
        {
            return false;
        }

        return true;
    }


    protected int revealSeedsSize(int[] hideList, int hideListSize)
    {
        int[] numNodesRevealed = new int[1];
        numNodesRevealed[0] = 0;
//        int[] revealed =
        getRevealedNodes(hideList, hideListSize, numNodesRevealed);
        return numNodesRevealed[0] * engine.seedSizeBytes;
    }

    protected int revealSeeds(int[] hideList, int hideListSize, byte[] output, int outputSize)
    {
//        byte[] outputBase = Arrays.clone(output);
        int[] revealedSize = new int[1];
        revealedSize[0] = 0;

//        if (outputSize > Integer.MAX_VALUE)
//        {
//            return -1;
//        }
        int outLen = outputSize;


        int[] revealed = getRevealedNodes(hideList, hideListSize, revealedSize);
        for (int i = 0; i < revealedSize[0]; i++)
        {
            outLen -= engine.seedSizeBytes;
            if (outLen < 0)
            {
                return 0;
            }
            System.arraycopy(this.nodes[revealed[i]], 0, output, i * engine.seedSizeBytes, engine.seedSizeBytes);
        }
        return output.length - outLen;
    }

    protected int openMerkleTreeSize(int[] missingLeaves, int missingLeavesSize)
    {
        int[] revealedSize = new int[1];
//        int[] revealed =
        getRevealedMerkleNodes(missingLeaves, missingLeavesSize, revealedSize);
        return revealedSize[0] * engine.digestSizeBytes;
    }

    /* Note that we never output the root node */
    private int[] getRevealedMerkleNodes(int[] missingLeaves, int missingLeavesSize, int[] outputSize)
    {
        int firstLeaf = this.numNodes - this.numLeaves;
        boolean[] missingNodes = new boolean[this.numNodes];

        /* Mark leaves that are missing */
        for (int i = 0; i < missingLeavesSize; i++)
        {
            missingNodes[firstLeaf + missingLeaves[i]] = true;
        }

        /* For the nonleaf nodes, if both leaves are missing, mark it as missing too */
        int lastNonLeaf = getParent(this.numNodes - 1);
        for (int i = lastNonLeaf; i > 0; i--)
        {
            if (!exists(i))
            {
                continue;
            }
            if (exists( 2 * i + 2))
            {
                if (missingNodes[2 * i + 1] && missingNodes[2 * i + 2])
                {
                    missingNodes[i] = true;
                }
            }
            else
            {
                if (missingNodes[2 * i + 1])
                {
                    missingNodes[i] = true;
                }
            }
        }

        /* For each missing leaf node, add the highest missing node on the path
         * back to the root to the set to be revealed */
        int[] revealed = new int[this.numLeaves];
        int pos = 0;
        for (int i = 0; i < missingLeavesSize; i++)
        {
            int node = missingLeaves[i] + firstLeaf;  /* input is leaf indexes, translate to nodes */
            do
            {
            if (!missingNodes[getParent(node)])
            {
                if (!contains(revealed, pos, node))
                {
                    revealed[pos] = node;
                    pos++;
                }
                break;
                }
            } while ((node = getParent(node)) != 0);
        }

        // free(missingNodes);
        outputSize[0] = pos;
        return revealed;
    }

    private boolean contains(int[] list, int len, int value)
    {
        for (int i = 0; i < len; i++)
        {
            if (list[i] == value)
            {
                return true;
            }
        }
        return false;
    }

    private void computeParentHash(int child, byte[] salt)
    {
        if (!exists(child))
        {
            return;
        }

        int parent = getParent(child);

        if (this.haveNode[parent])
        {
            return;
        }

        /* Compute the hash for parent, if we have everything */
        if (!this.haveNode[2 * parent + 1])
        {
            return;
        }

        if (exists(2 * parent + 2) && !this.haveNode[2 * parent + 2])
        {
            return;
        }

        /* Compute parent data = H(left child data || [right child data] || salt || parent idx) */
        engine.digest.update((byte) 3);
        engine.digest.update(this.nodes[2 * parent + 1],0, engine.digestSizeBytes);
        if (hasRightChild(parent))
        {
            /* One node may not have a right child when there's an odd number of leaves */
            engine.digest.update(this.nodes[2 * parent + 2],0, engine.digestSizeBytes);
        }
        engine.digest.update(salt,0, PicnicEngine.saltSizeBytes);
        engine.digest.update(Pack.intToLittleEndian(parent), 0, 2);
        engine.digest.doFinal(this.nodes[parent], 0, engine.digestSizeBytes);
        this.haveNode[parent] = true;
    }


    protected byte[] getLeaf(int leafIndex)
    {
//        assert(leafIndex < this.numLeaves);
        int firstLeaf = this.numNodes - this.numLeaves;
        return this.nodes[firstLeaf + leafIndex];
    }

    /* addMerkleNodes: deserialize and add the data for nodes provided by the committer */
    protected int addMerkleNodes(int[] missingLeaves, int missingLeavesSize, byte[] input, int inputSize)
    {
//        assert(missingLeavesSize < this.numLeaves);

//        if (inputSize > INT_MAX) {
//            return -1;
//        }

        int intLen = inputSize;

        int[] revealedSize = new int[1];
        revealedSize[0] = 0;
        int[] revealed = getRevealedMerkleNodes(missingLeaves, missingLeavesSize, revealedSize);
//        assert(!contains(revealed, revealedSize[0], 0));

        /* Deserialize input */
        for (int i = 0; i < revealedSize[0]; i++)
        {
            intLen -= this.dataSize;
            if (intLen < 0)
            {
                return -1;
            }
            System.arraycopy(input, i * this.dataSize, this.nodes[revealed[i]], 0, this.dataSize);
            this.haveNode[revealed[i]] = true;
        }

        if (intLen != 0)
        {
            return -1;
        }

        return 0;
    }

    protected void generateSeeds(byte[] rootSeed, byte[] salt, int repIndex)
    {
        this.nodes[0] = rootSeed;
        this.haveNode[0] = true;
        this.expandSeeds(salt, repIndex);
    }

    private void expandSeeds(byte[] salt, int repIndex)
    {
        byte[] tmp = new byte[2*MAX_SEED_SIZE_BYTES];

        /* Walk the tree, expanding seeds where possible. Compute children of
         * non-leaf nodes. */
        int lastNonLeaf = getParent(this.numNodes - 1);

        for (int i = 0; i <= lastNonLeaf; i++)
        {
            if (!this.haveNode[i])
            {
                continue;
            }

            hashSeed(tmp, this.nodes[i], salt, (byte) 1, repIndex, i);

            if (!this.haveNode[2 * i + 1])
            {
                /* left child = H_left(seed_i || salt || t || i) */
                System.arraycopy(tmp, 0, this.nodes[2 * i + 1], 0, engine.seedSizeBytes);
                this.haveNode[2 * i + 1] = true;
            }

            /* The last non-leaf node will only have a left child when there are an odd number of leaves */
            if (exists(2 * i + 2) && !this.haveNode[2 * i + 2])
            {
                /* right child = H_right(seed_i || salt || t || i)  */
                System.arraycopy(tmp, engine.seedSizeBytes, this.nodes[2 * i + 2], 0, engine.seedSizeBytes );
                this.haveNode[2 * i + 2] = true;
            }

        }
    }

    private void hashSeed(byte[] digest_arr, byte[] inputSeed, byte[] salt, byte hashPrefix, int repIndex, int nodeIndex)
    {
        engine.digest.update(hashPrefix);
        engine.digest.update(inputSeed, 0, engine.seedSizeBytes);
        engine.digest.update(salt, 0, PicnicEngine.saltSizeBytes);
        engine.digest.update(Pack.shortToLittleEndian((short)(repIndex & 0xffff)), 0, 2); //todo check endianness
        engine.digest.update(Pack.shortToLittleEndian((short)(nodeIndex & 0xffff)), 0, 2); //todo check endianness
        engine.digest.doFinal(digest_arr, 0, 2 * engine.seedSizeBytes);
//        System.out.println("hash: " + Hex.toHexString(digest_arr));
    }

    private boolean isLeftChild(int node)
    {
//        assert(node != 0);
        return(node % 2 == 1);
    }

    private boolean hasRightChild(int node)
    {
        return(2 * node + 2 < this.numNodes && (exists(node)));
    }

    boolean hasLeftChild(Tree tree, int node)
    {
        return(2 * node + 1 < this.numNodes);
    }

    private int getParent(int node)
    {
//        assert(node != 0);

        if (isLeftChild(node))
        {
            return (node - 1) / 2;
        }
        return (node - 2) / 2;
    }

    private boolean exists(int i)
    {
        if (i >= this.numNodes)
        {
            return false;
        }
        return this.exists[i];
    }

}
