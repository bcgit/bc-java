package org.bouncycastle.pqc.crypto.xmss;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.Arrays;

/**
 * WOTS+.
 */
final class WOTSPlus
{

    /**
     * WOTS+ parameters.
     */
    private final WOTSPlusParameters params;
    /**
     * Randomization functions.
     */
    private final KeyedHashFunctions khf;
    /**
     * WOTS+ secret key seed.
     */
    private byte[] secretKeySeed;
    /**
     * WOTS+ public seed.
     */
    private byte[] publicSeed;

    /**
     * Constructs a new WOTS+ one-time signature system based on the given WOTS+
     * parameters.
     *
     * @param params Parameters for WOTSPlus object.
     */
    WOTSPlus(WOTSPlusParameters params)
    {
        super();
        if (params == null)
        {
            throw new NullPointerException("params == null");
        }
        this.params = params;
        int n = params.getTreeDigestSize();
        khf = new KeyedHashFunctions(params.getTreeDigest(), n);
        secretKeySeed = new byte[n];
        publicSeed = new byte[n];
    }

    /**
     * Import keys to WOTS+ instance.
     *
     * @param secretKeySeed Secret key seed.
     * @param publicSeed    Public seed.
     */
    void importKeys(byte[] secretKeySeed, byte[] publicSeed)
    {
        if (secretKeySeed == null)
        {
            throw new NullPointerException("secretKeySeed == null");
        }
        if (secretKeySeed.length != params.getTreeDigestSize())
        {
            throw new IllegalArgumentException("size of secretKeySeed needs to be equal to size of digest");
        }
        if (publicSeed == null)
        {
            throw new NullPointerException("publicSeed == null");
        }
        if (publicSeed.length != params.getTreeDigestSize())
        {
            throw new IllegalArgumentException("size of publicSeed needs to be equal to size of digest");
        }
        this.secretKeySeed = secretKeySeed;
        this.publicSeed = publicSeed;
    }

    /**
     * Creates a signature for the n-byte messageDigest.
     *
     * @param messageDigest  Digest to sign.
     * @param otsHashAddress OTS hash address for randomization.
     * @return WOTS+ signature.
     */
    WOTSPlusSignature sign(byte[] messageDigest, OTSHashAddress otsHashAddress)
    {
        if (messageDigest == null)
        {
            throw new NullPointerException("messageDigest == null");
        }
        if (messageDigest.length != params.getTreeDigestSize())
        {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }
        List<Integer> baseWMessage = convertToBaseW(messageDigest, params.getWinternitzParameter(), params.getLen1());
        /* create checksum */
        int checksum = 0;
        for (int i = 0; i < params.getLen1(); i++)
        {
            checksum += params.getWinternitzParameter() - 1 - baseWMessage.get(i);
        }
        checksum <<= (8 - ((params.getLen2() * XMSSUtil.log2(params.getWinternitzParameter())) % 8));
        int len2Bytes = (int)Math
            .ceil((double)(params.getLen2() * XMSSUtil.log2(params.getWinternitzParameter())) / 8);
        List<Integer> baseWChecksum = convertToBaseW(XMSSUtil.toBytesBigEndian(checksum, len2Bytes),
            params.getWinternitzParameter(), params.getLen2());

		/* msg || checksum */
        baseWMessage.addAll(baseWChecksum);

		/* create signature */
        byte[][] signature = new byte[params.getLen()][];
        for (int i = 0; i < params.getLen(); i++)
        {
            otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder()
                .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                .withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(i)
                .withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())
                .build();
            signature[i] = chain(expandSecretKeySeed(i), 0, baseWMessage.get(i), otsHashAddress);
        }
        return new WOTSPlusSignature(params, signature);
    }

    /**
     * Calculates a public key based on digest and signature.
     *
     * @param messageDigest  The digest that was signed.
     * @param signature      Signarure on digest.
     * @param otsHashAddress OTS hash address for randomization.
     * @return WOTS+ public key derived from digest and signature.
     */
    WOTSPlusPublicKeyParameters getPublicKeyFromSignature(byte[] messageDigest, WOTSPlusSignature signature,
                                                                    OTSHashAddress otsHashAddress)
    {
        if (messageDigest == null)
        {
            throw new NullPointerException("messageDigest == null");
        }
        if (messageDigest.length != params.getTreeDigestSize())
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
        List<Integer> baseWMessage = convertToBaseW(messageDigest, params.getWinternitzParameter(), params.getLen1());
		/* create checksum */
        int checksum = 0;
        for (int i = 0; i < params.getLen1(); i++)
        {
            checksum += params.getWinternitzParameter() - 1 - baseWMessage.get(i);
        }
        checksum <<= (8 - ((params.getLen2() * XMSSUtil.log2(params.getWinternitzParameter())) % 8));
        int len2Bytes = (int)Math
            .ceil((double)(params.getLen2() * XMSSUtil.log2(params.getWinternitzParameter())) / 8);
        List<Integer> baseWChecksum = convertToBaseW(XMSSUtil.toBytesBigEndian(checksum, len2Bytes),
            params.getWinternitzParameter(), params.getLen2());

		/* msg || checksum */
        baseWMessage.addAll(baseWChecksum);

        byte[][] publicKey = new byte[params.getLen()][];
        for (int i = 0; i < params.getLen(); i++)
        {
            otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder()
                .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                .withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(i)
                .withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())
                .build();
            publicKey[i] = chain(signature.toByteArray()[i], baseWMessage.get(i),
                params.getWinternitzParameter() - 1 - baseWMessage.get(i), otsHashAddress);
        }
        return new WOTSPlusPublicKeyParameters(params, publicKey);
    }

    /**
     * Computes an iteration of F on an n-byte input using outputs of PRF.
     *
     * @param startHash      Starting point.
     * @param startIndex     Start index.
     * @param steps          Steps to take.
     * @param otsHashAddress OTS hash address for randomization.
     * @return Value obtained by iterating F for steps times on input startHash,
     * using the outputs of PRF.
     */
    private byte[] chain(byte[] startHash, int startIndex, int steps, OTSHashAddress otsHashAddress)
    {
        int n = params.getTreeDigestSize();
        if (startHash == null)
        {
            throw new NullPointerException("startHash == null");
        }
        if (startHash.length != n)
        {
            throw new IllegalArgumentException("startHash needs to be " + n + "bytes");
        }
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }
        if (otsHashAddress.toByteArray() == null)
        {
            throw new NullPointerException("otsHashAddress byte array == null");
        }
        if ((startIndex + steps) > params.getWinternitzParameter() - 1)
        {
            throw new IllegalArgumentException("max chain length must not be greater than w");
        }

        if (steps == 0)
        {
            return startHash;
        }

        byte[] tmp = chain(startHash, startIndex, steps - 1, otsHashAddress);
        otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(otsHashAddress.getChainAddress())
            .withHashAddress(startIndex + steps - 1).withKeyAndMask(0).build();
        byte[] key = khf.PRF(publicSeed, otsHashAddress.toByteArray());
        otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(otsHashAddress.getChainAddress())
            .withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(1).build();
        byte[] bitmask = khf.PRF(publicSeed, otsHashAddress.toByteArray());
        byte[] tmpMasked = new byte[n];
        for (int i = 0; i < n; i++)
        {
            tmpMasked[i] = (byte)(tmp[i] ^ bitmask[i]);
        }
        tmp = khf.F(key, tmpMasked);
        return tmp;
    }

    /**
     * Obtain base w values from Input.
     *
     * @param messageDigest Input data.
     * @param w             Base.
     * @param outLength     Length of output.
     * @return outLength-length list of base w integers.
     */
    private List<Integer> convertToBaseW(byte[] messageDigest, int w, int outLength)
    {
        if (messageDigest == null)
        {
            throw new NullPointerException("msg == null");
        }
        if (w != 4 && w != 16)
        {
            throw new IllegalArgumentException("w needs to be 4 or 16");
        }
        int logW = XMSSUtil.log2(w);
        if (outLength > ((8 * messageDigest.length) / logW))
        {
            throw new IllegalArgumentException("outLength too big");
        }

        ArrayList<Integer> res = new ArrayList<Integer>();
        for (int i = 0; i < messageDigest.length; i++)
        {
            for (int j = 8 - logW; j >= 0; j -= logW)
            {
                res.add((messageDigest[i] >> j) & (w - 1));
                if (res.size() == outLength)
                {
                    return res;
                }
            }
        }
        return res;
    }

    /**
     * Derive WOTS+ secret key for specific index as in XMSS ref impl Andreas
     * Huelsing.
     *
     * @param otsHashAddress one time hash address.
     * @return WOTS+ secret key at index.
     */
    protected byte[] getWOTSPlusSecretKey(byte[] secretKeySeed, OTSHashAddress otsHashAddress)
    {
        otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .withOTSAddress(otsHashAddress.getOTSAddress()).build();
        return khf.PRF(secretKeySeed, otsHashAddress.toByteArray());
    }

    /**
     * Derive private key at index from secret key seed.
     *
     * @param index Index.
     * @return Private key at index.
     */
    private byte[] expandSecretKeySeed(int index)
    {
        if (index < 0 || index >= params.getLen())
        {
            throw new IllegalArgumentException("index out of bounds");
        }
        return khf.PRF(secretKeySeed, XMSSUtil.toBytesBigEndian(index, 32));
    }

    /**
     * Getter parameters.
     *
     * @return params.
     */
    protected WOTSPlusParameters getParams()
    {
        return params;
    }

    /**
     * Getter keyed hash functions.
     *
     * @return keyed hash functions.
     */
    protected KeyedHashFunctions getKhf()
    {
        return khf;
    }

    /**
     * Getter secret key seed.
     *
     * @return secret key seed.
     */
    protected byte[] getSecretKeySeed()
    {
        return Arrays.clone(secretKeySeed);
    }

    /**
     * Getter public seed.
     *
     * @return public seed.
     */
    protected byte[] getPublicSeed()
    {
        return Arrays.clone(publicSeed);
    }

    /**
     * Getter private key.
     *
     * @return WOTS+ private key.
     */
    protected WOTSPlusPrivateKeyParameters getPrivateKey()
    {
        byte[][] privateKey = new byte[params.getLen()][];
        for (int i = 0; i < privateKey.length; i++)
        {
            privateKey[i] = expandSecretKeySeed(i);
        }
        return new WOTSPlusPrivateKeyParameters(params, privateKey);
    }

    /**
     * Calculates a new public key based on the state of secretKeySeed,
     * publicSeed and otsHashAddress.
     *
     * @param otsHashAddress OTS hash address for randomization.
     * @return WOTS+ public key.
     */
    WOTSPlusPublicKeyParameters getPublicKey(OTSHashAddress otsHashAddress)
    {
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }
        byte[][] publicKey = new byte[params.getLen()][];
		/* derive public key from secretKeySeed */
        for (int i = 0; i < params.getLen(); i++)
        {
            otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder()
                .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                .withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(i)
                .withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())
                .build();
            publicKey[i] = chain(expandSecretKeySeed(i), 0, params.getWinternitzParameter() - 1, otsHashAddress);
        }
        return new WOTSPlusPublicKeyParameters(params, publicKey);
    }
}
