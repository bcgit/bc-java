package org.bouncycastle.pqc.crypto.lms;

import java.util.List;

import org.bouncycastle.pqc.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.util.Arrays;

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

        // Step 1 and first part of Step 2
        keys[0] = LMS.generateKeys(
            parameters.getLmsParameters()[0].getLmsParam(),
            parameters.getLmsParameters()[0].getLmOTSParam(),
            0, I, rootSeed);

        // Step 2 -- This step could be deferred until first use.
        for (int i = 1; i < keys.length; i++)
        {
            SeedDerive deriver = keys[i - 1].getCurrentOTSKey().getDerivationFunction();
            deriver.setJ(~1);
            byte[] childRootSeed = new byte[32];
            deriver.deriveSeed(childRootSeed, true);
            byte[] postImage = new byte[32];
            deriver.deriveSeed(postImage, false);
            byte[] childI = new byte[16];
            System.arraycopy(postImage, 0, childI, 0, I.length);

            keys[i] = LMS.generateKeys(
                parameters.getLmsParameters()[i].getLmsParam(),
                parameters.getLmsParameters()[i].getLmOTSParam(),
                0, childI, childRootSeed);

            sig[i - 1] = LMS.generateSign(keys[i - 1], keys[i].getPublicKey().toByteArray());
        }

        return new HSSPrivateKeyParameters(parameters.getDepth(), keys, sig);
    }


    public static HSSSignature generateSignature(HSSPrivateKeyParameters keyPair, byte[] message)
    {

        /*
         * Theoretically it is possible for any HSS key index, that being the leaf index of the tree, to generate the
         * entire tree with only that index value, the root secret and root I value.
         *
         * The is inefficient because generating and signing the intermediate public keys is a fairly time consuming
         * activity. An alternative to this is cache, with all the problems caches bring, the signed public keys or
         * another alternative to this is to rely on the 99% use case which will be a monotonic consumption of this
         * hss private key.
         *
         * This this end this implementation will mutate the HSSPrivateKeyParameters with new derived intermediate keys
         * and signed public keys if they need to be changed. This will result in the minimum amount of overall work
         * in the general monotonic use case.
         */

        synchronized (keyPair)
        {
            if (keyPair.getIndex() >= keyPair.getIndexLimit())
            {
                throw new ExhaustedPrivateKeyException("hss private key" + ((keyPair.isLimited()) ? " shard" : "") + " is exhausted");
            }

            // Extract the original keys
            List<LMSPrivateKeyParameters> originalKeys = keyPair.getKeys();


            long[] qTreePath = new long[keyPair.getKeys().size()];
            long q = keyPair.getIndex();

            for (int t = keyPair.getKeys().size() - 1; t >= 0; t--)
            {
                LMSigParameters sigParameters = originalKeys.get(t).getSigParameters();
                int mask = (1 << sigParameters.getH()) - 1;
                qTreePath[t] = q & mask;
                q >>>= sigParameters.getH();
            }

            boolean changed = false;
            LMSPrivateKeyParameters[] keys = originalKeys.toArray(new LMSPrivateKeyParameters[originalKeys.size()]);//  new LMSPrivateKeyParameters[originalKeys.size()];
            LMSSignature[] sig = keyPair.getSig().toArray(new LMSSignature[keyPair.getSig().size()]);//   new LMSSignature[originalKeys.size() - 1];

            LMSPrivateKeyParameters originalRootKey = keyPair.getRootKey();


            //
            // We need to replace the root key to a new q value.
            //
            if (keys[0].getIndex() - 1 != qTreePath[0])
            {
                keys[0] = LMS.generateKeys(
                    originalRootKey.getSigParameters(),
                    originalRootKey.getOtsParameters(),
                    (int)qTreePath[0], originalRootKey.getI(), originalRootKey.getMasterSecret());
                changed = true;
            }


            for (int i = 1; i < qTreePath.length; i++)
            {

                LMSPrivateKeyParameters intermediateKey = keys[i - 1];

                byte[] childI = new byte[16];
                byte[] childSeed = new byte[32];
                SeedDerive derive = new SeedDerive(
                    intermediateKey.getI(),
                    intermediateKey.getMasterSecret(),
                    DigestUtil.getDigest(intermediateKey.getOtsParameters().getDigestOID()));
                derive.setQ((int)qTreePath[i - 1]);
                derive.setJ(~1);

                derive.deriveSeed(childSeed, true);
                byte[] postImage = new byte[32];
                derive.deriveSeed(postImage, false);
                System.arraycopy(postImage, 0, childI, 0, childI.length);

                //
                // Q values in LMS keys post increment after they are used.
                // For intermediate keys they will always be out by one from the derived q value (qValues[i])
                // For the end key its value will match so no correction is required.
                //
                boolean lmsQMatch =
                    (i < qTreePath.length - 1) ? qTreePath[i] == keys[i].getIndex() - 1 : qTreePath[i] == keys[i].getIndex();

                //
                // Equality is I and seed being equal and the lmsQMath.
                // I and seed are derived from this nodes parent and will change if the parent q, I, seed changes.
                //
                boolean seedEquals = Arrays.areEqual(childI, keys[i].getI())
                    && Arrays.areEqual(childSeed, keys[i].getMasterSecret());


                if (!seedEquals)
                {
                    //
                    // This means the parent has changed.
                    //
                    keys[i] = LMS.generateKeys(
                        originalKeys.get(i).getSigParameters(),
                        originalKeys.get(i).getOtsParameters(),
                        (int)qTreePath[i], childI, childSeed);

                    //
                    // Ensure post increment occurs on parent and the new public key is signed.
                    //
                    sig[i - 1] = LMS.generateSign(keys[i - 1], keys[i].getPublicKey().toByteArray());
                    changed = true;
                }
                else if (!lmsQMatch)
                {

                    //
                    // Q is different so we can generate a new private key but it will have the same public
                    // key so we do not need to sign it again.
                    //
                    keys[i] = LMS.generateKeys(
                        originalKeys.get(i).getSigParameters(),
                        originalKeys.get(i).getOtsParameters(),
                        (int)qTreePath[i], childI, childSeed);
                    changed = true;
                }

            }


            if (changed)
            {
                // We mutate the HSS key here!
                keyPair.updateHierarchy(keys, sig);
            }


            int L = keys.length;

            LMSPrivateKeyParameters nextKey = keys[L - 1];

            // Step 2. Stand in for sig[L-1]

            LMSSignature signatureResult = LMS.generateSign(nextKey, message);

            int i = 0;
            LMSSignedPubKey[] signed_pub_key = new LMSSignedPubKey[L - 1];
            while (i < L - 1)
            {
                signed_pub_key[i] = new LMSSignedPubKey(
                    sig[i],
                    keys[i + 1].getPublicKey());
                i = i + 1;
            }

            //
            // increment the index.
            //
            keyPair.incIndex();

            if (L == 1)
            {
                return new HSSSignature(L - 1, signed_pub_key, signatureResult);
            }

            return new HSSSignature(
                L - 1,
                signed_pub_key,
                signatureResult);
        }
    }


//    public static HSSSignature generateSignature(HSSPrivateKeyParameters keyPair, byte[] message)
//    {
//        int L = keyPair.getL();
//
//        //
//        // Algorithm 8
//        //
//        // Step 1.
//        LMSPrivateKeyParameters nextKey = keyPair.getNextSigningKey();
//
//        // Step 2. Stand in for sig[L-1]
//
//        LMSSignature signatureResult = LMS.generateSign(nextKey, message);
//
//        int i = 0;
//        LMSSignedPubKey[] signed_pub_key = new LMSSignedPubKey[L - 1];
//        while (i < L - 1)
//        {
//            signed_pub_key[i] = new LMSSignedPubKey(
//                keyPair.getSig().get(i),
//                keyPair.getKeys().get(i + 1).getPublicKey());
//            i = i + 1;
//        }
//
//        if (L == 1)
//        {
//            return new HSSSignature(L - 1, signed_pub_key, signatureResult);
//        }
//
//        return new HSSSignature(
//            L - 1,
//            signed_pub_key,
//            signatureResult);
//    }


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

        LMSPublicKeyParameters key = publicKey.getLmsPublicKey();

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


}
