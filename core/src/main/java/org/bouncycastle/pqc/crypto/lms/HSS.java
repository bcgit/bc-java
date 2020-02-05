package org.bouncycastle.pqc.crypto.lms;

import java.security.SecureRandom;
import java.util.List;

import org.bouncycastle.pqc.crypto.ExhaustedPrivateKeyException;

class HSS
{


//    /**
//     * This allows the creation of HSS Private key from 'l' number of
//     * (SEED,I) pairs. It then generates the OTS keys and the hierarchical signatures.
//     * <p>
//     * This parses 'l' number of:
//     * SEED [32 bytes]
//     * I [16 bytes]
//     * And applies the algorithm define in Appendix A of RFC 8554
//     * Link: https://tools.ietf.org/html/rfc8554#appendix-A
//     * <p>
//     * And creates the LM-OTS private keys.
//     * <p>
//     * It then generates the hierarchical signatures.
//     *
//     * @param l   the number of keys at that level.
//     * @param src The source, InputStream, byte[], HssPrivateKey
//     * @return
//     */
//    public static HssPrivateKey getPrivateKeyAppendixA(
//        LmsParameter lmsParameter,
//        LmOtsParameter otsParameter,
//        int l,
//        Object src)
//        throws LMSException
//    {
//        if (src instanceof HssPrivateKey)
//        {
//            return (HssPrivateKey)src;
//        }
//        else if (src instanceof DataInputStream)
//        {
//            try
//            {
//
//                LmsPrivateKey[] keys = new LmsPrivateKey[l];
//                LmsPublicKey[] publicKeys = new LmsPublicKey[l];
//                LMSSignature[] sig = new LMSSignature[l];
//
//                Digest H = otsParameter.getH(); // Digest comes from OTS parameters.
//                int twoToH = 1 << lmsParameter.getH(); // Not a digest function
//
//
//                for (int q = 0; q < l; q++)
//                {
//                    byte[][] otsPrivateKeys = new byte[twoToH][];
//
//                    //
//                    // Read in Seed and I
//                    //
//                    byte[] seed = new byte[32];
//                    ((DataInputStream)src).readFully(seed);
//                    byte[] I = new byte[16];
//                    ((DataInputStream)src).readFully(I);
//
//                    // Destination for digest.
//                    byte[] xq = new byte[H.getDigestSize()];
//
//                    LMSEntropySource es = new AppendixAEntropySource(otsParameter.getH(), I, q, seed);
//
//                    for (int i = 0; i < twoToH; i++)
//                    {
//                        otsPrivateKeys[i] = LM_OTS.generatePrivateKey(otsParameter, I, q, es);
//                    }
//
//                    keys[q] = new LmsPrivateKey(lmsParameter, otsParameter.getType(), q, I, otsPrivateKeys);
//                    publicKeys[q] = keys[q].getPublicKey();
//
//                    if (q > 0)
//                    {
//                        sig[q - 1] = LMS.generateSign(keys[q], keys[q - 1].getPublicKey().getEncoded(), es);
//                    }
//                }
//
//                return new HssPrivateKey(l, keys, keys[0].getPublicKey(), publicKeys, sig);
//
//            }
//            catch (LMSException lmex)
//            {
//                throw lmex;
//            }
//            catch (Exception ex)
//            {
//                throw new LMSException(ex.getMessage(), ex);
//            }
//        }
//        else if (src instanceof byte[])
//        {
//            return getPrivateKeyAppendixA(lmsParameter, otsParameter, l, new DataInputStream(new ByteArrayInputStream((byte[])src)));
//        }
//        else if (src instanceof InputStream)
//        {
//            return getPrivateKeyAppendixA(lmsParameter, otsParameter, l, new DataInputStream((InputStream)src));
//        }
//
//        throw new IllegalArgumentException("cannot parse " + src);
//    }


    public static HSSPrivateKeyParameters generateHSSKeyPair(HSSKeyGenerationParameters parameters)
    {
        //
        // LmsPrivateKey can derive and hold the public key so we just use an array of those.
        //
        LMSPrivateKeyParameters[] keys = new LMSPrivateKeyParameters[parameters.getDepth()];
        LMSSignature[] sig = new LMSSignature[parameters.getDepth()-1];

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
            SeedDerive deriver = keys[i-1].getCurrentOTSKey().getDerivationFunction();
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

            sig[i - 1] = LMS.generateSign(keys[i - 1], keys[i].getPublicKey().getEncoded());
        }

        return new HSSPrivateKeyParameters(parameters.getDepth(), keys, sig);
    }


    public static HSSSignature generateSignature(HSSPrivateKeyParameters keyPair, byte[] message, SecureRandom entropySource)
    {

        //
        // Algorithm 8
        //

        int L = keyPair.getL();

        int d = L;
        List<LMSPrivateKeyParameters> prv = keyPair.getKeys();
        while (prv.get(d - 1).getIndex() == 1 << (prv.get(d - 1).getParameters().getH()))
        {
            d = d - 1;
            if (d == 0)
            {
                throw new ExhaustedPrivateKeyException("hss key pair is exhausted");
            }
        }


        while (d < L)
        {
            keyPair.addNewKey(d, entropySource);
            d = d + 1;
        }

        // Step 2. Stand in for sig[L-1]


        LMSSignature signatureResult = LMS.generateSign(keyPair.getKeys().get(L - 1), message);

        int i = 0;
        LMSSignedPubKey[] signed_pub_key = new LMSSignedPubKey[L - 1];
        while (i < L - 1)
        {
            signed_pub_key[i] = new LMSSignedPubKey(
                keyPair.getSig().get(i),
                keyPair.getKeys().get(i + 1).getPublicKey());
            i = i + 1;
        }


        if (L == 1)
        {
            return new HSSSignature(L - 1, signed_pub_key, signatureResult);
        }


        return new HSSSignature(
            L - 1,
            signed_pub_key,   //LMSSignedPubKey.sliceTo(signed_pub_key, signed_pub_key.length),
            signatureResult);


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

        LMSPublicKeyParameters key = publicKey.getLmsPublicKey();

        for (int i = 0; i < Nspk; i++)
        {
            LMSSignature sig = sigList[i];
            byte[] msg = pubList[i].getEncoded();
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
