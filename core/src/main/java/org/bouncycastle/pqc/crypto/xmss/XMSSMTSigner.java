package org.bouncycastle.pqc.crypto.xmss;

import java.util.Map;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.StatefulMessageSigner;
import org.bouncycastle.util.Arrays;

/**
 * XMSS^MT Signer class.
 */
public class XMSSMTSigner
    implements StatefulMessageSigner
{
    private XMSSMTPrivateKeyParameters privateKey;
    private XMSSMTPublicKeyParameters publicKey;
    private XMSSMTParameters params;
    private XMSS xmss;

    private WOTSPlus wotsPlus;

    private boolean initSign;

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            initSign = true;
            privateKey = (XMSSMTPrivateKeyParameters)param;

            params = privateKey.getParameters();
            xmss = params.getXMSS();
        }
        else
        {
            initSign = false;
            publicKey = (XMSSMTPublicKeyParameters)param;

            params = publicKey.getParameters();
            xmss = params.getXMSS();
        }

        wotsPlus = new WOTSPlus(new WOTSPlusParameters(params.getDigest()));
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
        if (privateKey.getBDSState().isEmpty())
        {
            throw new IllegalStateException("not initialized");
        }

        Map<Integer, BDS> bdsState = privateKey.getBDSState();

        // privateKey.increaseIndex(this);
        long globalIndex = privateKey.getIndex();
        int totalHeight = params.getHeight();
        int xmssHeight = xmss.getParams().getHeight();
        if (!XMSSUtil.isIndexValid(totalHeight, globalIndex))
        {
            throw new IllegalStateException("index out of bounds");
        }

      		/* compress message */
        byte[] random = wotsPlus.getKhf().PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(globalIndex, 32));
        byte[] concatenated = XMSSUtil.concat(random, privateKey.getRoot(),
            XMSSUtil.toBytesBigEndian(globalIndex, params.getDigestSize()));
        byte[] messageDigest = wotsPlus.getKhf().HMsg(concatenated, message);

        XMSSMTSignature signature = new XMSSMTSignature.Builder(params).withIndex(globalIndex).withRandom(random).build();


      		/* layer 0 */
        long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
        int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);

      		/* reset xmss */
        xmss.setIndex(indexLeaf);
        xmss.setPublicSeed(privateKey.getPublicSeed());

      		/* create signature with XMSS tree on layer 0 */

      		/* adjust addresses */
        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withTreeAddress(indexTree)
            .withOTSAddress(indexLeaf).build();

      		/* sign message digest */
        WOTSPlusSignature wotsPlusSignature = xmss.wotsSign(messageDigest, otsHashAddress);
      		/* get authentication path from BDS */
        if (bdsState.get(0) == null || indexLeaf == 0)
        {
            bdsState.put(0, new BDS(xmss));
            bdsState.get(0).initialize(xmss.getPrivateKey(), otsHashAddress);
        }

        XMSSReducedSignature reducedSignature = new XMSSReducedSignature.Builder(xmss.getParams())
                .withWOTSPlusSignature(wotsPlusSignature).withAuthPath(bdsState.get(0).getAuthenticationPath())
                .build();

        signature.getReducedSignatures().add(reducedSignature);

      		/* prepare authentication path for next leaf */
        if (indexLeaf < ((1 << xmssHeight) - 1))
        {
            bdsState.get(0).nextAuthenticationPath(xmss.getPrivateKey(), otsHashAddress);
        }

      		/* loop over remaining layers */
        for (int layer = 1; layer < params.getLayers(); layer++)
        {
      			/* get root of layer - 1 */
            XMSSNode root = bdsState.get(layer - 1).getRoot();

            indexLeaf = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
            indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);
            xmss.setIndex(indexLeaf);

      			/* adjust addresses */
            otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withLayerAddress(layer)
                .withTreeAddress(indexTree).withOTSAddress(indexLeaf).build();

      			/* sign root digest of layer - 1 */
            wotsPlusSignature = xmss.wotsSign(root.getValue(), otsHashAddress);
      			/* get authentication path from BDS */
            if (bdsState.get(layer) == null || XMSSUtil.isNewBDSInitNeeded(globalIndex, xmssHeight, layer))
            {
                bdsState.put(layer, new BDS(xmss));
                bdsState.get(layer).initialize(xmss.getPrivateKey(), otsHashAddress);
            }

            reducedSignature = new XMSSReducedSignature.Builder(xmss.getParams())
                    .withWOTSPlusSignature(wotsPlusSignature)
                    .withAuthPath(bdsState.get(layer).getAuthenticationPath()).build();

            signature.getReducedSignatures().add(reducedSignature);

      			/* prepare authentication path for next leaf */
            if (indexLeaf < ((1 << xmssHeight) - 1)
                && XMSSUtil.isNewAuthenticationPathNeeded(globalIndex, xmssHeight, layer))
            {
                bdsState.get(layer).nextAuthenticationPath(xmss.getPrivateKey(), otsHashAddress);
            }
        }

        /* update private key */
        privateKey = new XMSSMTPrivateKeyParameters.Builder(params).withIndex(globalIndex + 1)
            .withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
            .withPublicSeed(privateKey.getPublicSeed()).withRoot(privateKey.getRoot())
            .withBDSState(privateKey.getBDSState()).build();

        return signature.toByteArray();
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

        byte[] concatenated = XMSSUtil.concat(sig.getRandom(), publicKey.getRoot(),
            XMSSUtil.toBytesBigEndian(sig.getIndex(), params.getDigestSize()));
        byte[] messageDigest = wotsPlus.getKhf().HMsg(concatenated, message);

        long globalIndex = sig.getIndex();
        int xmssHeight = xmss.getParams().getHeight();
        long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
        int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);

		/* adjust xmss */
        wotsPlus.importKeys(new byte[params.getDigestSize()], publicKey.getPublicSeed());
        
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

    public AsymmetricKeyParameter getUpdatedPrivateKey()
    {
        XMSSMTPrivateKeyParameters privKey = privateKey;

        privateKey = null;

        return privKey;
    }
}
