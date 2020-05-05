package org.bouncycastle.pqc.crypto.lms;

import java.util.List;

import org.bouncycastle.pqc.crypto.ExhaustedPrivateKeyException;

class HSS
{

    public static HSSPrivateKeyParameters generateHSSKeyPair(HSSKeyGenerationParameters parameters)
    {
        //
        // LmsPrivateKey can derive and hold the public key so we just use an array of those.
        //
        LMSPrivateKeyParameters[] keys = new LMSPrivateKeyParameters[parameters.getDepth()];
        LMSSignature[] sig = new LMSSignature[parameters.getDepth() - 1];

        byte[] rootSeed = new byte[32];
        parameters.getRandom().nextBytes(rootSeed);

        byte[] I = new byte[16];
        parameters.getRandom().nextBytes(I);

        //
        // Set the HSS key up with a valid root LMSPrivateKeyParameters and placeholders for the remaining LMS keys.
        // The placeholders pass enough information to allow the HSSPrivateKeyParameters to be properly reset to an
        // index of zero. Rather than repeat the same reset-to-index logic in this static method.
        //

        byte[] zero = new byte[0];

        long hssKeyMaxIndex = 1;
        for (int t = 0; t < keys.length; t++)
        {
            if (t == 0)
            {
                keys[t] = new LMSPrivateKeyParameters(
                    parameters.getLmsParameters()[t].getLMSigParam(),
                    parameters.getLmsParameters()[t].getLMOTSParam(),
                    0,
                    I,
                    1 << parameters.getLmsParameters()[t].getLMSigParam().getH(),
                    rootSeed);
            }
            else
            {
                keys[t] = new PlaceholderLMSPrivateKey(
                    parameters.getLmsParameters()[t].getLMSigParam(),
                    parameters.getLmsParameters()[t].getLMOTSParam(),
                    -1,
                    zero,
                    1 << parameters.getLmsParameters()[t].getLMSigParam().getH(),
                    zero);
            }
            hssKeyMaxIndex *= 1 << parameters.getLmsParameters()[t].getLMSigParam().getH();
        }

        // if this has happened we're trying to generate a really large key
        // we'll use MAX_VALUE so that it's at least usable until someone upgrades the structure.
        if (hssKeyMaxIndex == 0)
        {
            hssKeyMaxIndex = Long.MAX_VALUE;
        }

        return new HSSPrivateKeyParameters(
            parameters.getDepth(),
            java.util.Arrays.asList(keys),
            java.util.Arrays.asList(sig),
            0, hssKeyMaxIndex);
    }

    /**
     * Increments an HSS private key without doing any work on it.
     * HSS private keys are automatically incremented when when used to create signatures.
     * <p>
     * The HSS private key is ranged tested before this incrementation is applied.
     * LMS keys will be replaced as required.
     *
     * @param keyPair
     */
    public static void incrementIndex(HSSPrivateKeyParameters keyPair)
    {
        synchronized (keyPair)
        {
            rangeTestKeys(keyPair);
            keyPair.incIndex();
            keyPair.getKeys().get(keyPair.getL() - 1).incIndex();
        }
    }


    static void rangeTestKeys(HSSPrivateKeyParameters keyPair)
    {
        synchronized (keyPair)
        {
            if (keyPair.getIndex() >= keyPair.getIndexLimit())
            {
                throw new ExhaustedPrivateKeyException(
                    "hss private key" +
                        ((keyPair.isShard()) ? " shard" : "") +
                        " is exhausted");
            }


            int L = keyPair.getL();
            int d = L;
            List<LMSPrivateKeyParameters> prv = keyPair.getKeys();
            while (prv.get(d - 1).getIndex() == 1 << (prv.get(d - 1).getSigParameters().getH()))
            {
                d = d - 1;
                if (d == 0)
                {
                    throw new ExhaustedPrivateKeyException(
                        "hss private key" +
                            ((keyPair.isShard()) ? " shard" : "") +
                            " is exhausted the maximum limit for this HSS private key");
                }
            }


            while (d < L)
            {
                keyPair.replaceConsumedKey(d);
                d = d + 1;
            }
        }
    }


    public static HSSSignature generateSignature(HSSPrivateKeyParameters keyPair, byte[] message)
    {
        LMSSignedPubKey[] signed_pub_key;
        LMSPrivateKeyParameters nextKey;
        int L = keyPair.getL();

        synchronized (keyPair)
        {
            rangeTestKeys(keyPair);

            List<LMSPrivateKeyParameters> keys = keyPair.getKeys();
            List<LMSSignature> sig = keyPair.getSig();

            nextKey = keyPair.getKeys().get(L - 1);

            // Step 2. Stand in for sig[L-1]
            int i = 0;
            signed_pub_key = new LMSSignedPubKey[L - 1];
            while (i < L - 1)
            {
                signed_pub_key[i] = new LMSSignedPubKey(
                    sig.get(i),
                    keys.get(i + 1).getPublicKey());
                i = i + 1;
            }

            //
            // increment the index.
            //
            keyPair.incIndex();
        }

        LMSContext context = nextKey.generateLMSContext().withSignedPublicKeys(signed_pub_key);

        context.update(message, 0, message.length);

        return generateSignature(L, context);
    }

    public static HSSSignature generateSignature(int L, LMSContext context)
    {
        return new HSSSignature(L - 1, context.getSignedPubKeys(), LMS.generateSign(context));
    }

    public static boolean verifySignature(HSSPublicKeyParameters publicKey, HSSSignature signature, byte[] message)
    {
        int Nspk = signature.getlMinus1();
        if (Nspk + 1 != publicKey.getL())
        {
            return false;
        }

        LMSSignature[] sigList = new LMSSignature[Nspk + 1];
        LMSPublicKeyParameters[] pubList = new LMSPublicKeyParameters[Nspk];

        for (int i = 0; i < Nspk; i++)
        {
            sigList[i] = signature.getSignedPubKey()[i].getSignature();
            pubList[i] = signature.getSignedPubKey()[i].getPublicKey();
        }
        sigList[Nspk] = signature.getSignature();

        LMSPublicKeyParameters key = publicKey.getLMSPublicKey();

        for (int i = 0; i < Nspk; i++)
        {
            LMSSignature sig = sigList[i];
            byte[] msg = pubList[i].toByteArray();
            if (!LMS.verifySignature(key, sig, msg))
            {
                return false;
            }
            try
            {
                key = pubList[i];
            }
            catch (Exception ex)
            {
                throw new IllegalStateException(ex.getMessage(), ex);
            }
        }
        return LMS.verifySignature(key, sigList[Nspk], message);
    }


    static class PlaceholderLMSPrivateKey
        extends LMSPrivateKeyParameters
    {

        public PlaceholderLMSPrivateKey(LMSigParameters lmsParameter, LMOtsParameters otsParameters, int q, byte[] I, int maxQ, byte[] masterSecret)
        {
            super(lmsParameter, otsParameters, q, I, maxQ, masterSecret);
        }

        @Override
        LMOtsPrivateKey getNextOtsPrivateKey()
        {
            throw new RuntimeException("placeholder only");
        }

        @Override
        public LMSPublicKeyParameters getPublicKey()
        {
            throw new RuntimeException("placeholder only");
        }
    }

}
