package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class LM_OTS
{

    private static final short D_PBLC = (short)0x8080;
    private static final int ITER_K = 20;
    private static final int ITER_PREV = 23;
    private static final int ITER_J = 22;
    private static final int SEED_RANDOMISER_INDEX = ~2;
    private static final int SEED_LEN = 32;
    private static final int MAX_HASH = 32;



    private static final short D_MESG = (short)0x8181;


    public static int coef(byte[] S, int i, int w)
    {
        int index = (i * w) / 8;
        int digits_per_byte = 8 / w;
        int shift = w * (~i & (digits_per_byte - 1));
        int mask = (1 << w) - 1;

        return (S[index] >>> shift) & mask;
    }


    public static int cksm(byte[] S, int sLen, LMOtsParameters parameters)
    {
        int sum = 0;

        int w = parameters.getW();

        // NB assumption about size of "w" not overflowing integer.
        int twoWpow = (1 << w) - 1;

        for (int i = 0; i < (sLen * 8 / parameters.getW()); i++)
        {
            sum = sum + twoWpow - coef(S, i, parameters.getW());
        }
        return sum << parameters.getLs();
    }


    public static LMOtsPublicKey lms_ots_generatePublicKey(LMOtsPrivateKey privateKey)
    {
        byte[] K = lms_ots_generatePublicKey(privateKey.getParameter(), privateKey.getI(), privateKey.getQ(), privateKey.getMasterSecret());
        return new LMOtsPublicKey(privateKey.getParameter(), privateKey.getI(), privateKey.getQ(), K);
    }

    static byte[] lms_ots_generatePublicKey(LMOtsParameters parameter, byte[] I, int q, byte[] masterSecret)
    {


        //
        // Start hash that computes the final value.
        //
        Digest publicContext = DigestUtil.getDigest(parameter.getDigestOID());
        byte[] prehashPrefix = Composer.compose()
            .bytes(I)
            .u32str(q)
            .u16str(D_PBLC)
            .padUntil(0, 22)
            .build();
        publicContext.update(prehashPrefix, 0, prehashPrefix.length);

        Digest ctx = DigestUtil.getDigest(parameter.getDigestOID());

        byte[] buf = Composer.compose()
            .bytes(I)
            .u32str(q)
            .padUntil(0, 23 + ctx.getDigestSize())
            .build();


        SeedDerive derive = new SeedDerive(I, masterSecret, DigestUtil.getDigest(parameter.getDigestOID()));
        derive.setQ(q);
        derive.setJ(0);

        int p = parameter.getP();
        int n = parameter.getN();
        final int twoToWminus1 = (1 << parameter.getW()) - 1;


        for (int i = 0; i < p; i++)
        {
            derive.deriveSeed(buf, i < p - 1, ITER_PREV); // Private Key!
            Pack.shortToBigEndian((short)i, buf, ITER_K);
            for (int j = 0; j < twoToWminus1; j++)
            {
                buf[ITER_J] = (byte)j;
                ctx.update(buf, 0, buf.length);
                ctx.doFinal(buf, ITER_PREV);
            }
            publicContext.update(buf, ITER_PREV, n);
        }

        byte[] K = new byte[publicContext.getDigestSize()];
        publicContext.doFinal(K, 0);

        return K;

    }

    public static LMOtsSignature lm_ots_generate_signature(LMOtsPrivateKey privateKey, byte[] message, boolean preHashed)
    {

        LMOtsParameters parameter = privateKey.getParameter();

        int n = parameter.getN();
        int p = parameter.getP();
        int w = parameter.getW();


        byte[] sigComposer = new byte[p * n];

        //
        // Add the randomizer.
        //

        byte[] C = new byte[SEED_LEN];

        if (!preHashed)
        {
            SeedDerive derive = privateKey.getDerivationFunction();
            derive.setJ(SEED_RANDOMISER_INDEX); // This value from reference impl.
            derive.deriveSeed(C, false);
        }

        SeedDerive derive = privateKey.getDerivationFunction();


        byte[] Q = new byte[MAX_HASH + 2];

        Digest ctx = DigestUtil.getDigest(parameter.getDigestOID());

        if (!preHashed)
        {
            LmsUtils.byteArray(privateKey.getI(), ctx);
            LmsUtils.u32str(privateKey.getQ(), ctx);
            LmsUtils.u16str(D_MESG, ctx);
            LmsUtils.byteArray(C, ctx);
            LmsUtils.byteArray(message, 0, message.length, ctx);
            ctx.doFinal(Q, 0);
        }
        else
        {
            System.arraycopy(message, 0, Q, 0, n);
        }

        int cs = cksm(Q, n, parameter);
        Q[n] = (byte)((cs >>> 8) & 0xFF);
        Q[n + 1] = (byte)cs;

        byte[] tmp = Composer.compose().bytes(privateKey.getI()).u32str(privateKey.getQ()).padUntil(0, ITER_PREV + n).build();

        derive.setJ(0);
        for (int i = 0; i < p; i++)
        {
            Pack.shortToBigEndian((short)i, tmp, ITER_K);
            derive.deriveSeed(tmp, i < p - 1, ITER_PREV);
            int a = coef(Q, i, w);
            for (int j = 0; j < a; j++)
            {
                tmp[ITER_J] = (byte)j;
                ctx.update(tmp, 0, ITER_PREV + n);
                ctx.doFinal(tmp, ITER_PREV);
            }
            System.arraycopy(tmp, ITER_PREV, sigComposer, n * i, n);
        }

        return new LMOtsSignature(parameter, C, sigComposer);

    }


    public static boolean lm_ots_validate_signature(LMOtsPublicKey publicKey, LMOtsSignature signature, byte[] message, boolean prehashed)
        throws LMSException
    {
        if (!signature.getType().equals(publicKey.getParameter()))
        {
            throw new LMSException("public key and signature ots types do not match");
        }
        return Arrays.areEqual(lm_ots_validate_signature_calculate(publicKey.getParameter(), publicKey.getI(), publicKey.getQ(), signature, message, prehashed), publicKey.getK());
    }

    public static byte[] lm_ots_validate_signature_calculate(LMOtsParameters parameter, byte[] I, int q, LMOtsSignature signature, byte[] message, boolean prehashed)
    {

        byte[] C = signature.getC();
        byte[] y = signature.getY();

        byte[] Q = new byte[MAX_HASH + 2];
        if (prehashed)
        {
            System.arraycopy(message, 0, Q, 0, parameter.getN());
        }
        else
        {
            Digest ctx = DigestUtil.getDigest(parameter.getDigestOID());
            LmsUtils.byteArray(I, ctx);
            LmsUtils.u32str(q, ctx);
            LmsUtils.u16str(D_MESG, ctx);
            LmsUtils.byteArray(C, ctx);
            LmsUtils.byteArray(message, ctx);
            ctx.doFinal(Q, 0);
        }

        int n = parameter.getN();
        int w = parameter.getW();
        int p = parameter.getP();


        int cs = cksm(Q, n, parameter);
        Q[n] = (byte)((cs >>> 8) & 0xFF);
        Q[n + 1] = (byte)cs;


        Digest finalContext = DigestUtil.getDigest(parameter.getDigestOID());
        LmsUtils.byteArray(I, finalContext);
        LmsUtils.u32str(q, finalContext);
        LmsUtils.u16str(D_PBLC, finalContext);


        byte[] tmp = Composer.compose()
            .bytes(I)
            .u32str(q)
            .padUntil(0, ITER_PREV + n).build();

        int max_digit = (1 << w) - 1;


        Digest ctx = DigestUtil.getDigest(parameter.getDigestOID());
        for (int i = 0; i < p; i++)
        {
            Pack.shortToBigEndian((short)i, tmp, ITER_K);
            System.arraycopy(y, i * n, tmp, ITER_PREV, n);
            int a = coef(Q, i, w);

            for (int j = a; j < max_digit; j++)
            {
                tmp[ITER_J] = (byte)j;
                ctx.update(tmp, 0, ITER_PREV + n);
                ctx.doFinal(tmp, ITER_PREV);
            }

            finalContext.update(tmp, ITER_PREV, n);
        }

        byte[] K = new byte[n];
        finalContext.doFinal(K, 0);

        return K;
    }

}
