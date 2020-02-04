package org.bouncycastle.pqc.crypto.lms;

import java.util.Stack;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;

public class LMS
{
    private static final short D_LEAF = (short)0x8282;
    private static final short D_INTR = (short)0x8383;

    public static LMSPrivateKeyParameters generateKeys(LmsParameter parameterSet, LmOtsParameter lmOtsParameters, int level, byte[] I, byte[] rootSeed)
        throws LMSException
    {
        //
        // RFC 8554 recommends that digest used in LMS and LMOTS be of the same strength to protect against
        // attackers going after the weaker of the two digests. This is not enforced here!
        //

        // Algorithm 5, Compute LMS private key.

        // Step 1
        // -- Parameters passed in as arguments.


        // Step 2

        if (rootSeed == null || rootSeed.length < parameterSet.getM())
        {
            throw new LMSException("root seed is less than " + parameterSet.getM());
        }


        int twoToH = 1 << parameterSet.getH();


        return new LMSPrivateKeyParameters(parameterSet, lmOtsParameters, level, I, twoToH, rootSeed);
    }


    public static LMSSignature generateSign(LMSPrivateKeyParameters privateKey, byte[] message)
        throws LMSException
    {

        //
        // Get T from the public key.
        // This may cause the public key to be generated.
        //
        // byte[][] T = new byte[privateKey.getMaxQ()][];

        // Step 1.
        LmsParameter lmsParameter = privateKey.getParameterSet();

        // Step 2
        int h = lmsParameter.getH();

        int q = privateKey.getQ();
        LmOtsPrivateKey otsPk = privateKey.getNextOtsPrivateKey();

        // LmsPrivateKey.KeyWithQ keyWithQ = privateKey.getNextOtsPrivateKey();

        LMOtsSignature ots_signature = LM_OTS.lm_ots_generate_signature(otsPk, message, false);

        // Step 3;
//        LMOtsSignature ots_signature = LM_OTS.generateSignature(
//            LmOtsParameters.getOtsParameter(privateKey.getLmOtsType()),
//            ,
//            message,
//            source);


        // Step 4;
        //  int q = privateKey.getQ();


        // byte[][] T = generateTArray(privateKey,privateKey.getPublicKey());


        int i = 0;
        int r = (1 << h) + q;
        byte[][] path = new byte[h][];
    
        while (i < h)
        {
            int tmp = (r / (1 << i)) ^ 1;
            path[i] = findT(tmp, privateKey, privateKey.getParameterSet().getDigest());
            i++;
        }

        return new LMSSignature(q, ots_signature, lmsParameter, path);
    }


    public static byte[] findT(int r, LMSPrivateKeyParameters privateKey, Digest digest)
    {


        int h = privateKey.getParameterSet().getH();

        int twoToh = 1 << h;

        byte[] T;

        // r is a base 1 index.


        if (r >= (1 << h))
        {
            LmsUtils.byteArray(privateKey.getI(), digest);
            LmsUtils.u32str(r, digest);
            LmsUtils.u16str(D_LEAF, digest);

            //
            // These can be pre generated at the time of key generation and held within the private key.
            // However it will cost memory to have them stick around.
            //
            byte[] K = LM_OTS.lms_ots_generatePublicKey(privateKey.getLmOtsType(), privateKey.getI(), (r - twoToh), privateKey.getMasterSecret());

            LmsUtils.byteArray(K, digest);
            T = new byte[digest.getDigestSize()];
            digest.doFinal(T, 0);
            return T;
        }

        byte[] t2r = findT(2 * r, privateKey, digest);
        byte[] t2rPlus1 = findT((2 * r + 1), privateKey, digest);

        LmsUtils.byteArray(privateKey.getI(), digest);
        LmsUtils.u32str(r, digest);
        LmsUtils.u16str(D_INTR, digest);
        LmsUtils.byteArray(t2r, digest);
        LmsUtils.byteArray(t2rPlus1, digest);
        T = new byte[digest.getDigestSize()];
        digest.doFinal(T, 0);

        return T;

    }


    public static boolean verifySignature(LMSSignature S, byte[] message, LMSPublicKeyParameters publicKey)
        throws LMSException
    {
        byte[] Tc = algorithm6a(S, publicKey.getI(), publicKey.getParameterSet().getType(), publicKey.getLmOtsType().getType(), message);
        return Arrays.areEqual(publicKey.getT1(), Tc);
    }


    public static byte[] algorithm6a(LMSSignature S, byte[] I, int lMpubType, int ots_typecode, byte[] message)
        throws LMSException
    {
        // Step 1.
//        if (S.length < 8)
//        {
//            throw new IllegalArgumentException("signature must be at least eight bytes");
//        }

        // Step 2a
        int q = S.getQ(); //  Pack.bigEndianToInt(S, 0);

//        // Step 2b
//        int otssigtype =  S.  Pack.bigEndianToInt(S, 4);


        // Step 2c
        if (S.getOtsSignature().getType().getType() != ots_typecode)
        {
            throw new IllegalArgumentException("ots type from lsm signature does not match ots" +
                " signature type from embedded ots signature");
        }


        // Step 2d
//        LmOtsParameter otsParameter = LmOtsParameters.getOtsParameter(otssigtype);
//        int n = otsParameter.getN();
//        int p = otsParameter.getP();
//        if (S.length < 12 + n * (p + 1))
//        {
//            throw new IllegalArgumentException("S must be at least " + (12 + n * (p + 1)) + " bytes");
//        }

        // Step 2e
//        byte[] lmots_signature = new byte[(((7 + n * (p + 1))) - 4) + 1];
//        System.arraycopy(S, 4, lmots_signature, 0, lmots_signature.length);
//
//        // Step 2f
//        int sigType = Pack.bigEndianToInt(S, (8 + n * (p + 1)));
//
//        // Step 2g
//        if (sigType != lMpubType)
//        {
//            throw new IllegalArgumentException("lm ");
//        }
//
//        // Step 2h
        LmsParameter lmsParameter = S.getParameter();
        int m = lmsParameter.getM();
        int h = lmsParameter.getH();
//
//
//        // Step 2i
//        if (q > (1 << h) || S.length != 12 + n * (p + 1) + m * h)
//        {
//            throw new IllegalArgumentException("S has incorrect length.");
//        }
//
//
//        // Step 2j
//        int pos = (8 + n * (p + 1)) + 4;
        byte[][] path = S.getY();
//        for (int i = 0; i < h; i++)
//        {
//            path[i] = new byte[m];
//            System.arraycopy(S, pos, path[i], 0, m);
//            pos += m;
//        }

        // Step 3
        byte[] Kc = LM_OTS.lm_ots_validate_signature_calculate(
            LmOtsParameters.getOtsParameter(ots_typecode),
            I,
            q,
            S.getOtsSignature(),
            message, false);


        // Step 4
        // node_num = 2^h + q
        int node_num = (1 << h) + q;

        // tmp = H(I || u32str(node_num) || u16str(D_LEAF) || Kc)
        Digest H = lmsParameter.getDigest();
        byte[] tmp = new byte[H.getDigestSize()];

        H.update(I, 0, I.length);
        LmsUtils.u32str(node_num, H);
        LmsUtils.u16str(D_LEAF, H);
        H.update(Kc, 0, Kc.length);
        H.doFinal(tmp, 0);

        int i = 0;

        while (node_num > 1)
        {
            if ((node_num & 1) == 1)
            {
                // is odd
                H.update(I, 0, I.length);
                LmsUtils.u32str(node_num / 2, H);
                LmsUtils.u16str(D_INTR, H);
                H.update(path[i], 0, path[i].length);
                H.update(tmp, 0, tmp.length);
                H.doFinal(tmp, 0);
            }
            else
            {
                H.update(I, 0, I.length);
                LmsUtils.u32str(node_num / 2, H);
                LmsUtils.u16str(D_INTR, H);
                H.update(tmp, 0, tmp.length);
                H.update(path[i], 0, path[i].length);
                H.doFinal(tmp, 0);
            }
            node_num = node_num / 2;
            i++;
        }
        return tmp;
    }


    static byte[] appendixC(LMSPrivateKeyParameters lmsPrivateKey)
        throws LMSException
    {

        LmOtsParameter otsParameter = LmOtsParameters.getOtsParameter(lmsPrivateKey.getLmOtsType());

        int twoToh = 1 << lmsPrivateKey.getParameterSet().getH();
        Digest H = lmsPrivateKey.getParameterSet().getDigest();
        Stack<byte[]> stack = new Stack<byte[]>();
        byte[] I = lmsPrivateKey.getI();
        for (int i = 0; i < twoToh; i++)
        {
            int r = i + twoToh; //OTS_PUB.length;
            byte[] temp = new byte[H.getDigestSize()];
            H.update(I, 0, I.length);
            LmsUtils.u32str(r, H);
            LmsUtils.u16str(D_LEAF, H);
            byte[] K = LM_OTS.lms_ots_generatePublicKey(otsParameter, lmsPrivateKey.getI(), i, lmsPrivateKey.getMasterSecret());
            H.update(K, 0, K.length);
            H.doFinal(temp, 0);
            int j = i;
            while (j % 2 == 1)
            {
                r = (r - 1) / 2;
                j = (j - 1) / 2;
                byte[] leftSide = stack.pop();
                H.update(I, 0, I.length);
                LmsUtils.u32str(r, H);
                LmsUtils.u16str(D_INTR, H);
                H.update(leftSide, 0, leftSide.length);
                H.update(temp, 0, temp.length);
                H.doFinal(temp, 0);
            }
            stack.push(temp);
        }
        return stack.pop();
    }

}
