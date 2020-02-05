package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.pqc.crypto.StateAwareMessageSigner;
import org.bouncycastle.util.Arrays;

public class XMSSSigner
    implements StateAwareMessageSigner
{
    private XMSSPrivateKeyParameters privateKey;
    private XMSSPublicKeyParameters publicKey;
    private XMSSParameters params;
    private WOTSPlus wotsPlus;
    private KeyedHashFunctions khf;

    private boolean initSign;
    private boolean hasGenerated;

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            initSign = true;
            hasGenerated = false;
            privateKey = (XMSSPrivateKeyParameters)param;
            params = privateKey.getParameters();
        }
        else
        {
            initSign = false;
            publicKey = (XMSSPublicKeyParameters)param;

            params = publicKey.getParameters();
        }

        wotsPlus = params.getWOTSPlus();
        khf = wotsPlus.getKhf();
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
                throw new ExhaustedPrivateKeyException("no usages of private key remaining");
            }
            if (privateKey.getBDSState().getAuthenticationPath().isEmpty())
            {
                throw new IllegalStateException("not initialized");
            }

            try
            {
                int index = privateKey.getIndex();

                hasGenerated = true;

                /* create (randomized keyed) messageDigest of message */
                byte[] random = khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(index, 32));
                byte[] concatenated = Arrays.concatenate(random, privateKey.getRoot(),
                    XMSSUtil.toBytesBigEndian(index, params.getTreeDigestSize()));
                byte[] messageDigest = khf.HMsg(concatenated, message);

                /* create signature for messageDigest */
                OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withOTSAddress(index).build();
                WOTSPlusSignature wotsPlusSignature = wotsSign(messageDigest, otsHashAddress);
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
    }

    public long getUsagesRemaining()
    {
        return privateKey.getUsagesRemaining();
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        /* parse signature and public key */
        XMSSSignature sig = new XMSSSignature.Builder(params).withSignature(signature).build();
                /* generate public key */

        int index = sig.getIndex();
        		/* reinitialize WOTS+ object */
        wotsPlus.importKeys(new byte[params.getTreeDigestSize()], publicKey.getPublicSeed());

        		/* create message digest */
        byte[] concatenated = Arrays.concatenate(sig.getRandom(), publicKey.getRoot(),
            XMSSUtil.toBytesBigEndian(index, params.getTreeDigestSize()));
        byte[] messageDigest = khf.HMsg(concatenated, message);

        int xmssHeight = params.getHeight();
        int indexLeaf = XMSSUtil.getLeafIndex(index, xmssHeight);

        		/* get root from signature */
        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withOTSAddress(index).build();
        XMSSNode rootNodeFromSignature = XMSSVerifierUtil.getRootNodeFromSignature(wotsPlus, xmssHeight, messageDigest, sig, otsHashAddress, indexLeaf);

        return Arrays.constantTimeAreEqual(rootNodeFromSignature.getValue(), publicKey.getRoot());
    }

    public AsymmetricKeyParameter getUpdatedPrivateKey()
    {
        // if we've generated a signature return the last private key generated
        // if we've only initialised leave it in place and return the next one instead.
        synchronized (privateKey)
        {
            if (hasGenerated)
            {
                XMSSPrivateKeyParameters privKey = privateKey;

                privateKey = null;

                return privKey;
            }
            else
            {
                XMSSPrivateKeyParameters privKey = privateKey;

                if (privKey != null)
                {
                    privateKey = privateKey.getNextKey();
                }

                return privKey;
            }
        }
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
}
