package org.bouncycastle.pqc.crypto.xmss;

class XMSSVerifierUtil
{
    /**
     * Compute a root node from a tree signature.
     *
     * @param messageDigest Message digest.
     * @param signature     XMSS signature.
     * @return Root node calculated from signature.
     */
    static XMSSNode getRootNodeFromSignature(WOTSPlus wotsPlus, int height, byte[] messageDigest, XMSSReducedSignature signature,
                                              OTSHashAddress otsHashAddress, int indexLeaf)
    {
        if (messageDigest.length != wotsPlus.getParams().getTreeDigestSize())
        {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        if (signature == null)
        {
            throw new NullPointerException("signature == null");
        }
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }

		/* prepare adresses */
        LTreeAddress lTreeAddress = (LTreeAddress)new LTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .withLTreeAddress(otsHashAddress.getOTSAddress()).build();
        HashTreeAddress hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .withTreeIndex(otsHashAddress.getOTSAddress()).build();
		/*
		 * calculate WOTS+ public key and compress to obtain original leaf hash
		 */
        WOTSPlusPublicKeyParameters wotsPlusPK = wotsPlus.getPublicKeyFromSignature(messageDigest,
            signature.getWOTSPlusSignature(), otsHashAddress);
        XMSSNode[] node = new XMSSNode[2];
        node[0] = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPK, lTreeAddress);

        for (int k = 0; k < height; k++)
        {
            hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
                .withLayerAddress(hashTreeAddress.getLayerAddress())
                .withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(k)
                .withTreeIndex(hashTreeAddress.getTreeIndex()).withKeyAndMask(hashTreeAddress.getKeyAndMask())
                .build();
            if (Math.floor(indexLeaf / (1 << k)) % 2 == 0)
            {
                hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
                    .withLayerAddress(hashTreeAddress.getLayerAddress())
                    .withTreeAddress(hashTreeAddress.getTreeAddress())
                    .withTreeHeight(hashTreeAddress.getTreeHeight())
                    .withTreeIndex(hashTreeAddress.getTreeIndex() / 2)
                    .withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
                node[1] = XMSSNodeUtil.randomizeHash(wotsPlus, node[0], signature.getAuthPath().get(k), hashTreeAddress);
                node[1] = new XMSSNode(node[1].getHeight() + 1, node[1].getValue());
            }
            else
            {
                hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
                    .withLayerAddress(hashTreeAddress.getLayerAddress())
                    .withTreeAddress(hashTreeAddress.getTreeAddress())
                    .withTreeHeight(hashTreeAddress.getTreeHeight())
                    .withTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2)
                    .withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
                node[1] = XMSSNodeUtil.randomizeHash(wotsPlus, signature.getAuthPath().get(k), node[0], hashTreeAddress);
                node[1] = new XMSSNode(node[1].getHeight() + 1, node[1].getValue());
            }
            node[0] = node[1];
        }
        return node[0];
    }
}
