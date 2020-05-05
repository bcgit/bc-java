package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;

class LMS
{
    static final short D_LEAF = (short)0x8282;
    static final short D_INTR = (short)0x8383;

    public static LMSPrivateKeyParameters generateKeys(LMSigParameters parameterSet, LMOtsParameters lmOtsParameters, int q, byte[] I, byte[] rootSeed)
        throws IllegalArgumentException
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
            throw new IllegalArgumentException("root seed is less than " + parameterSet.getM());
        }

        int twoToH = 1 << parameterSet.getH();

        return new LMSPrivateKeyParameters(parameterSet, lmOtsParameters, q, I, twoToH, rootSeed);
    }

    public static LMSSignature generateSign(LMSPrivateKeyParameters privateKey, byte[] message)
    {
        //
        // Get T from the public key.
        // This may cause the public key to be generated.
        //
        // byte[][] T = new byte[privateKey.getMaxQ()][];
        
        // Step 2
        LMSContext context = privateKey.generateLMSContext();

        context.update(message, 0, message.length);

        return generateSign(context);
    }

    public static LMSSignature generateSign(LMSContext context)
    {
        //
        // Get T from the public key.
        // This may cause the public key to be generated.
        //
        // byte[][] T = new byte[privateKey.getMaxQ()][];

        // Step 1.
        LMOtsSignature ots_signature = LM_OTS.lm_ots_generate_signature(context.getPrivateKey(), context.getQ(), context.getC());

        return new LMSSignature(context.getPrivateKey().getQ(), ots_signature, context.getSigParams(), context.getPath());
    }

//    public static boolean verifySignature(LMSPublicKeyParameters publicKey, LMSSignature S, byte[] message)
//    {
//        byte[] Tc = algorithm6a(S, publicKey.refI(), publicKey.getOtsParameters().getType(), message);
//
//        return publicKey.matchesT1(Tc);
//    }

    public static boolean verifySignature(LMSPublicKeyParameters publicKey, LMSSignature S, byte[] message)
    {
        LMSContext context = publicKey.generateOtsContext(S);

        LmsUtils.byteArray(message, context);

        return verifySignature(publicKey, context);
    }

    public static boolean verifySignature(LMSPublicKeyParameters publicKey, byte[] S, byte[] message)
    {
        LMSContext context = publicKey.generateLMSContext(S);

        LmsUtils.byteArray(message, context);

        return verifySignature(publicKey, context);
    }

    public static boolean verifySignature(LMSPublicKeyParameters publicKey, LMSContext context)
    {


        LMSSignature S = (LMSSignature)context.getSignature();
                LMSigParameters lmsParameter = S.getParameter();
                int h = lmsParameter.getH();
                byte[][] path = S.getY();
                byte[] Kc = LM_OTS.lm_ots_validate_signature_calculate(context);
                // Step 4
                // node_num = 2^h + q
                int node_num = (1 << h) + S.getQ();

                // tmp = H(I || u32str(node_num) || u16str(D_LEAF) || Kc)
                byte[] I = publicKey.getI();
                Digest H = DigestUtil.getDigest(lmsParameter.getDigestOID());
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
         byte[] Tc = tmp;
        return publicKey.matchesT1(Tc);
    }

    public static byte[] algorithm6a(LMSSignature S, byte[] I, int ots_typecode, byte[] message)
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

//        for (int i = 0; i < h; i++)
//        {
//            path[i] = new byte[m];
//            System.arraycopy(S, pos, path[i], 0, m);
//            pos += m;
//        }

        // Step 3
//        byte[] Kc = LM_OTS.lm_ots_validate_signature_calculate(
//            LMOtsParameters.getParametersForType(ots_typecode),
//            I,
//            q,
//            S.getOtsSignature(),
//            message, false);
        LMSContext ctx = new LMOtsPublicKey(LMOtsParameters.getParametersForType(ots_typecode), I, q, null).createOtsContext(S);

        LmsUtils.byteArray(message, ctx);

        LMSigParameters lmsParameter = S.getParameter();
        int h = lmsParameter.getH();
        byte[][] path = S.getY();
        byte[] Kc = LM_OTS.lm_ots_validate_signature_calculate(ctx);
        // Step 4
        // node_num = 2^h + q
        int node_num = (1 << h) + q;

        // tmp = H(I || u32str(node_num) || u16str(D_LEAF) || Kc)
        Digest H = DigestUtil.getDigest(lmsParameter.getDigestOID());
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
}
