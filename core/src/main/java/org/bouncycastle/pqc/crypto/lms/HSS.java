package org.bouncycastle.pqc.crypto.lms;

import java.security.SecureRandom;

class HSS
{



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

            sig[i - 1] = LMS.generateSign(keys[i - 1], keys[i].getPublicKey().toByteArray());
        }

        return new HSSPrivateKeyParameters(parameters.getDepth(), keys, sig);
    }


    public static HSSSignature generateSignature(HSSPrivateKeyParameters keyPair, byte[] message, SecureRandom entropySource)
    {
        int L = keyPair.getL();

        //
        // Algorithm 8
        //
        // Step 1.
        LMSPrivateKeyParameters nextKey = keyPair.getNextSigningKey(entropySource);

        // Step 2. Stand in for sig[L-1]

        LMSSignature signatureResult = LMS.generateSign(nextKey, message);

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
            signed_pub_key,
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
