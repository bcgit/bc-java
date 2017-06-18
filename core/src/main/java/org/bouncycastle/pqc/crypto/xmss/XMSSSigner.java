package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.StatefulMessageSigner;
import org.bouncycastle.util.Arrays;

public class XMSSSigner
    implements StatefulMessageSigner
{
    private XMSSPrivateKeyParameters privateKey;
    private XMSSPublicKeyParameters publicKey;
    private XMSSParameters params;
    private KeyedHashFunctions khf;

    private boolean initSign;

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            initSign = true;
            privateKey = (XMSSPrivateKeyParameters)param;

            params = privateKey.getParameters();
            khf = params.getWOTSPlus().getKhf();
        }
        else
        {
            initSign = false;
            publicKey = (XMSSPublicKeyParameters)param;

            params = publicKey.getParameters();
            khf = params.getWOTSPlus().getKhf();
        }
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
                throw new IllegalStateException("signer key no longer usable");
            }
        }
        else
        {
            throw new IllegalStateException("signer not initialized for signature generation");
        }
        if (privateKey.getBDSState().getAuthenticationPath().isEmpty())
        {
            throw new IllegalStateException("not initialized");
        }
        int index = privateKey.getIndex();
        if (!XMSSUtil.isIndexValid(params.getHeight(), index))
        {
            throw new IllegalStateException("index out of bounds");
        }

		/* create (randomized keyed) messageDigest of message */
        byte[] random = khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(index, 32));
        byte[] concatenated = XMSSUtil.concat(random, privateKey.getRoot(),
            XMSSUtil.toBytesBigEndian(index, params.getDigestSize()));
        byte[] messageDigest = khf.HMsg(concatenated, message);

		/* create signature for messageDigest */
        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withOTSAddress(index).build();
        WOTSPlusSignature wotsPlusSignature = wotsSign(messageDigest, otsHashAddress);
        XMSSSignature signature = (XMSSSignature)new XMSSSignature.Builder(params).withIndex(index).withRandom(random)
            .withWOTSPlusSignature(wotsPlusSignature).withAuthPath(privateKey.getBDSState().getAuthenticationPath())
            .build();


		/* prepare authentication path for next leaf */
        int treeHeight = this.params.getHeight();
        if (index < ((1 << treeHeight) - 1))
        {
            privateKey.getBDSState().nextAuthenticationPath((OTSHashAddress)new OTSHashAddress.Builder().build());
        }

        /* update index */
        privateKey = new XMSSPrivateKeyParameters.Builder(params).withIndex(index + 1)
            .withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
            .withPublicSeed(privateKey.getPublicSeed()).withRoot(privateKey.getRoot())
            .withBDSState(privateKey.getBDSState()).build();

        return signature.toByteArray();
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        /* parse signature and public key */
        XMSSSignature sig = new XMSSSignature.Builder(params).withSignature(signature).build();
                /* generate public key */

        int index = sig.getIndex();
        		/* reinitialize WOTS+ object */
        params.getWOTSPlus().importKeys(new byte[params.getDigestSize()], publicKey.getPublicSeed());

        		/* create message digest */
        byte[] concatenated = XMSSUtil.concat(sig.getRandom(), publicKey.getRoot(),
            XMSSUtil.toBytesBigEndian(index, params.getDigestSize()));
        byte[] messageDigest = khf.HMsg(concatenated, message);

        int xmssHeight = params.getHeight();
        int indexLeaf = XMSSUtil.getLeafIndex(index, xmssHeight);

        		/* get root from signature */
        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withOTSAddress(index).build();
        XMSSNode rootNodeFromSignature = XMSSVerifierUtil.getRootNodeFromSignature(params.getWOTSPlus(), xmssHeight, messageDigest, sig, otsHashAddress, indexLeaf);

        return Arrays.constantTimeAreEqual(rootNodeFromSignature.getValue(), publicKey.getRoot());
    }

    public AsymmetricKeyParameter getFinalPrivateKey()
    {
        XMSSPrivateKeyParameters privKey = privateKey;

        privateKey = null;

        return privKey;
    }

    private WOTSPlusSignature wotsSign(byte[] messageDigest, OTSHashAddress otsHashAddress)
    {
        if (messageDigest.length != params.getDigestSize())
        {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }
        /* (re)initialize WOTS+ instance */
        params.getWOTSPlus().importKeys(getWOTSPlusSecretKey(otsHashAddress), privateKey.getPublicSeed());
		/* create WOTS+ signature */
        return params.getWOTSPlus().sign(messageDigest, otsHashAddress);
    }

    /**
     * Derive WOTS+ secret key for specific index as in XMSS ref impl Andreas
     * Huelsing.
     *
     * @param otsHashAddress
     * @return WOTS+ secret key at index.
     */
    private byte[] getWOTSPlusSecretKey(OTSHashAddress otsHashAddress)
    {
        otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .withOTSAddress(otsHashAddress.getOTSAddress()).build();
        return khf.PRF(privateKey.getSecretKeySeed(), otsHashAddress.toByteArray());
    }
}
