package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.StateAwareMessageSigner;
import org.bouncycastle.util.Arrays;

/**
 * XMSS^MT Signer class.
 */
public class XMSSMTSigner
    implements StateAwareMessageSigner
{
    private XMSSMTPrivateKeyParameters privateKey;
    private XMSSMTPublicKeyParameters publicKey;
    private XMSSMTParameters params;
    private XMSSParameters xmssParams;

    private WOTSPlus wotsPlus;

    private boolean hasGenerated;
    private boolean initSign;

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            initSign = true;
            hasGenerated = false;
            privateKey = (XMSSMTPrivateKeyParameters)param;

            params = privateKey.getParameters();
            xmssParams = params.getXMSSParameters();
        }
        else
        {
            initSign = false;
            publicKey = (XMSSMTPublicKeyParameters)param;

            params = publicKey.getParameters();
            xmssParams = params.getXMSSParameters();
        }
        
        wotsPlus = params.getWOTSPlus();
    }

    public byte[] generateSignature(byte[] message)
    {
        if (message == null)
        {
            throw new NullPointerException("message == null");
        }

        if (initSign)
        {
            if (privateKey == null)
            {
                throw new IllegalStateException("signing key no longer usable");
            }
        }
        else
        {
            throw new IllegalStateException("signer not initialized for signature generation");
        }

        synchronized (privateKey)
        {
            if (privateKey.getUsagesRemaining() <= 0)
            {
                throw new IllegalStateException("no usages of private key remaining");
            }
            if (privateKey.getBDSState().isEmpty())
            {
                throw new IllegalStateException("not initialized");
            }

            try
            {

                BDSStateMap bdsState = privateKey.getBDSState();

                // privateKey.increaseIndex(this);
                final long globalIndex = privateKey.getIndex();
                final int totalHeight = params.getHeight();
                final int xmssHeight = xmssParams.getHeight();
                if (privateKey.getUsagesRemaining() <= 0)
                {
                    throw new IllegalStateException("index out of bounds");
                }

                /* compress message */
                byte[] random = wotsPlus.getKhf().PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(globalIndex, 32));
                byte[] concatenated = Arrays.concatenate(random, privateKey.getRoot(),
                    XMSSUtil.toBytesBigEndian(globalIndex, params.getTreeDigestSize()));
                byte[] messageDigest = wotsPlus.getKhf().HMsg(concatenated, message);

                hasGenerated = true;

                XMSSMTSignature signature = new XMSSMTSignature.Builder(params).withIndex(globalIndex).withRandom(random).build();


                /* layer 0 */
                long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
                int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);

                /* reset xmss */
                wotsPlus.importKeys(new byte[params.getTreeDigestSize()], privateKey.getPublicSeed());
                /* create signature with XMSS tree on layer 0 */

                /* adjust addresses */
                OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withTreeAddress(indexTree)
                    .withOTSAddress(indexLeaf).build();

                /* get authentication path from BDS */
                if (bdsState.get(0) == null || indexLeaf == 0)
                {
                    bdsState.put(0, new BDS(xmssParams, privateKey.getPublicSeed(), privateKey.getSecretKeySeed(), otsHashAddress));
                }

                /* sign message digest */
                WOTSPlusSignature wotsPlusSignature = wotsSign(messageDigest, otsHashAddress);

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
                    otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withLayerAddress(layer)
                        .withTreeAddress(indexTree).withOTSAddress(indexLeaf).build();

                    /* sign root digest of layer - 1 */
                    wotsPlusSignature = wotsSign(root.getValue(), otsHashAddress);
                    /* get authentication path from BDS */
                    if (bdsState.get(layer) == null || XMSSUtil.isNewBDSInitNeeded(globalIndex, xmssHeight, layer))
                    {
                        bdsState.put(layer, new BDS(xmssParams, privateKey.getPublicSeed(), privateKey.getSecretKeySeed(), otsHashAddress));
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
                privateKey.rollKey();
            }
        }
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        if (message == null)
        {
            throw new NullPointerException("message == null");
        }
        if (signature == null)
        {
            throw new NullPointerException("signature == null");
        }
        if (publicKey == null)
        {
            throw new NullPointerException("publicKey == null");
        }
		/* (re)create compressed message */
        XMSSMTSignature sig = new XMSSMTSignature.Builder(params).withSignature(signature).build();

        byte[] concatenated = Arrays.concatenate(sig.getRandom(), publicKey.getRoot(),
                                         XMSSUtil.toBytesBigEndian(sig.getIndex(), params.getTreeDigestSize()));
        byte[] messageDigest = wotsPlus.getKhf().HMsg(concatenated, message);

        long globalIndex = sig.getIndex();
        int xmssHeight = xmssParams.getHeight();
        long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
        int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);

		/* adjust xmss */
        wotsPlus.importKeys(new byte[params.getTreeDigestSize()], publicKey.getPublicSeed());
        
		/* prepare addresses */
        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withTreeAddress(indexTree)
            .withOTSAddress(indexLeaf).build();

		/* get root node on layer 0 */
        XMSSReducedSignature xmssMTSignature = sig.getReducedSignatures().get(0);
        XMSSNode rootNode = XMSSVerifierUtil.getRootNodeFromSignature(wotsPlus, xmssHeight, messageDigest, xmssMTSignature, otsHashAddress, indexLeaf);
        for (int layer = 1; layer < params.getLayers(); layer++)
        {
            xmssMTSignature = sig.getReducedSignatures().get(layer);
            indexLeaf = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
            indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);

			/* adjust address */
            otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withLayerAddress(layer)
                .withTreeAddress(indexTree).withOTSAddress(indexLeaf).build();

			/* get root node */
            rootNode = XMSSVerifierUtil.getRootNodeFromSignature(wotsPlus, xmssHeight, rootNode.getValue(), xmssMTSignature, otsHashAddress, indexLeaf);
        }

		/* compare roots */
        return Arrays.constantTimeAreEqual(rootNode.getValue(), publicKey.getRoot());
    }

    private WOTSPlusSignature wotsSign(byte[] messageDigest, OTSHashAddress otsHashAddress)
    {
        if (messageDigest.length != params.getTreeDigestSize())
        {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }
		/* (re)initialize WOTS+ instance */
        wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(privateKey.getSecretKeySeed(), otsHashAddress), privateKey.getPublicSeed());
		/* create WOTS+ signature */
        return wotsPlus.sign(messageDigest, otsHashAddress);
    }

    public long getUsagesRemaining()
    {
        return privateKey.getUsagesRemaining();
    }

    public AsymmetricKeyParameter getUpdatedPrivateKey()
    {
        // if we've generated a signature return the last private key generated
        // if we've only initialised leave it in place and return the next one instead.
        if (hasGenerated)
        {
            XMSSMTPrivateKeyParameters privKey = privateKey;

            privateKey = null;

            return privKey;
        }
        else
        {
            XMSSMTPrivateKeyParameters privKey = privateKey;

            if (privKey != null)
            {
                privateKey = privateKey.getNextKey();
            }

            return privKey;
        }
    }
}
