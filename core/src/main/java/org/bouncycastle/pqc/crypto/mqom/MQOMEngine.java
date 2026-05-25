package org.bouncycastle.pqc.crypto.mqom;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.crypto.mqom.MQOMParameters;
import org.bouncycastle.util.Arrays;

/**
 * MQOM v2.1 top-level engine. Generic across all 48 parameter sets:
 * key generation, signing, and verification. Pick the parameter set via
 * {@link #getInstance(MQOMParameters)}.
 */
final class MQOMEngine
{
    private final MQOMParameters params;
    private final MQOMSymmetric sym;
    private final MQOMBLC blc;
    private final MQOMPiop piop;

    private final int seedSize;
    private final int saltSize;
    private final int digestSize;
    private final int tau;
    private final int nbEvalsLog;
    private final int w;
    private final int mqN;
    private final int eta;
    private final int extBytesPerElt;
    private final int extLog2;
    private final int pkSize;
    private final int skSize;
    private final int sigSize;

    /*
     * Scratch — only buffers holding *public* values are kept as instance
     * fields. The sign-side witness shares (x0/u0/u1/alpha0/alpha1), the
     * unpacked witness (xPacked), and the sk-derived mseedEq are allocated
     * per call so secret material does not linger in the engine's heap state.
     */
    private final byte[] scratchMsgHash;     // digestSize  (Hash2 output)
    private final byte[] scratchCom1;        // digestSize  (becomes sig)
    private final byte[] scratchCom2;        // digestSize  (becomes sig)
    private final byte[] scratchHash;        // digestSize  (Hash4 output)
    private final int[]  scratchIStar;       // tau         (verifier challenge)
    private final byte[] scratchTmp;         // tau*2 + 2   (Hash5 output)

    private MQOMEngine(MQOMParameters params)
    {
        this.params = params;
        this.sym = new MQOMSymmetric(params);
        this.blc = new MQOMBLC(sym);
        this.piop = new MQOMPiop(sym);

        this.seedSize = params.getSeedSize();
        this.saltSize = params.getSaltSize();
        this.digestSize = params.getDigestSize();
        this.tau = params.getTau();
        this.nbEvalsLog = params.getNbEvalsLog();
        this.w = params.getW();
        this.mqN = params.getMqN();
        this.eta = params.getEta();
        this.extLog2 = params.getExtFieldLog2();
        this.extBytesPerElt = extLog2 / 8;
        this.pkSize = params.getPublicKeySize();
        this.skSize = params.getPrivateKeySize();
        this.sigSize = params.getSignatureSize();

        this.scratchMsgHash = new byte[digestSize];
        this.scratchCom1 = new byte[digestSize];
        this.scratchCom2 = new byte[digestSize];
        this.scratchHash = new byte[digestSize];
        this.scratchIStar = new int[tau];
        this.scratchTmp = new byte[tau * 2 + 2];
    }

    public static MQOMEngine getInstance(MQOMParameters params)
    {
        if (params == null)
        {
            throw new NullPointerException("params");
        }
        return new MQOMEngine(params);
    }

    public MQOMParameters getParameters()
    {
        return params;
    }

    /* ============================ KeyGen ============================= */

    public void keyGen(byte[] seedKey, byte[] sk, byte[] pk)
    {
        if (seedKey.length != 2 * seedSize)
        {
            throw new IllegalArgumentException("seedKey length wrong: expected " + (2 * seedSize)
                + " bytes, got " + seedKey.length);
        }
        if (sk.length != skSize)
        {
            throw new IllegalArgumentException("sk length wrong: expected " + skSize
                + " bytes, got " + sk.length);
        }
        if (pk.length != pkSize)
        {
            throw new IllegalArgumentException("pk length wrong: expected " + pkSize
                + " bytes, got " + pk.length);
        }

        byte[] xBytes = new byte[params.getByteSizeFieldBase(mqN)];
        byte[] mseedEq = new byte[2 * seedSize];

        SHAKEDigest xof = sym.newXof();
        sym.xofUpdateTag(xof, 0);
        xof.update(seedKey, 0, 2 * seedSize);
        byte[] combined = new byte[xBytes.length + 2 * seedSize];
        sym.xofSqueeze(xof, combined, 0, combined.length);
        System.arraycopy(combined, 0, xBytes, 0, xBytes.length);
        System.arraycopy(combined, xBytes.length, mseedEq, 0, 2 * seedSize);

        // Compute y_i = x^T A_i x + b_i^T x (in K) for i = 0..m-1.
        int m = params.getMqM() / params.getMu();
        byte[] aHat = new byte[m * mqN * mqN * extBytesPerElt];
        byte[] bHat = new byte[m * mqN * extBytesPerElt];
        new MQOMExpand(sym).expand(mseedEq, aHat, bHat);

        int yBytes = m * extBytesPerElt;
        byte[] y = new byte[yBytes];
        byte[] vec = new byte[mqN * extBytesPerElt];

        for (int i = 0; i < m; i++)
        {
            int matOff = i * mqN * mqN * extBytesPerElt;
            int bOff = i * mqN * extBytesPerElt;
            int yi;
            if (extLog2 == 8)
            {
                MQOMField.extBaseMatMultTriInf_gf256(params.getBaseFieldLog2(),
                    aHat, matOff, xBytes, 0, vec, 0, mqN);
                yi = MQOMField.baseExtVectMult_baseToGf256(params.getBaseFieldLog2(),
                    xBytes, 0, vec, 0, mqN);
                yi ^= MQOMField.baseExtVectMult_baseToGf256(params.getBaseFieldLog2(),
                    xBytes, 0, bHat, bOff, mqN);
                y[i] = (byte)(yi & 0xFF);
            }
            else
            {
                MQOMField.extBaseMatMultTriInf_gf256to2(params.getBaseFieldLog2(),
                    aHat, matOff, xBytes, 0, vec, 0, mqN);
                yi = MQOMField.baseExtVectMult_baseToGf256to2(params.getBaseFieldLog2(),
                    xBytes, 0, vec, 0, mqN);
                yi ^= MQOMField.baseExtVectMult_baseToGf256to2(params.getBaseFieldLog2(),
                    xBytes, 0, bHat, bOff, mqN);
                MQOMField.gf256to2PutElt(y, 0, i, yi);
            }
        }

        // pk = mseed_eq || y
        System.arraycopy(mseedEq, 0, pk, 0, 2 * seedSize);
        System.arraycopy(y, 0, pk, 2 * seedSize, yBytes);

        // sk = pk || x
        System.arraycopy(pk, 0, sk, 0, pkSize);
        System.arraycopy(xBytes, 0, sk, pkSize, xBytes.length);
    }

    /* ============================ Sign =============================== */

    public byte[] sign(byte[] sk, byte[] msg, byte[] salt, byte[] mseed)
    {
        if (sk.length != skSize)
        {
            throw new IllegalArgumentException("sk length wrong: expected " + skSize
                + " bytes, got " + sk.length);
        }
        if (salt.length != saltSize)
        {
            throw new IllegalArgumentException("salt length wrong: expected " + saltSize
                + " bytes, got " + salt.length);
        }
        if (mseed.length != seedSize)
        {
            throw new IllegalArgumentException("mseed length wrong: expected " + seedSize
                + " bytes, got " + mseed.length);
        }

        byte[] sig = new byte[sigSize];

        int pos = 0;
        System.arraycopy(salt, 0, sig, pos, saltSize);
        pos += saltSize;
        int com1Off = pos;
        pos += digestSize;
        int com2Off = pos;
        pos += digestSize;
        int serializedAlpha1Off = pos;
        int alpha1Block = params.getByteSizeFieldBase(eta * params.getMu());
        pos += tau * alpha1Block;
        int openingOff = pos;
        int nonceOff = sigSize - 4;

        // pk is sk[0..pkSize] — feed sk directly to xof4 below; no separate clone.
        // mseedEq is the public first 2*seedSize bytes of pk, but on the sign
        // side it is read from sk; xPacked IS the secret witness. Both are
        // allocated per call so witness-derived material does not linger.
        byte[] mseedEq = new byte[2 * seedSize];
        System.arraycopy(sk, 0, mseedEq, 0, 2 * seedSize);
        byte[] xPacked = new byte[params.getByteSizeFieldBase(mqN)];
        System.arraycopy(sk, pkSize, xPacked, 0, xPacked.length);

        // msg_hash
        byte[] msgHash = scratchMsgHash;
        SHAKEDigest xof = sym.newXof();
        sym.xofUpdateTag(xof, 2);
        xof.update(msg, 0, msg.length);
        sym.xofSqueeze(xof, msgHash, 0, digestSize);

        // BLC.Commit — the MPC-in-the-Head shares x0/u0/u1 carry secret
        // information correlated with the witness; allocated per call.
        MQOMBLC.Key key = new MQOMBLC.Key();
        int nExtBytes = mqN * extBytesPerElt;
        int etaExtBytes = eta * extBytesPerElt;
        byte[][] x0 = new byte[tau][nExtBytes];
        byte[][] u0 = new byte[tau][etaExtBytes];
        byte[][] u1 = new byte[tau][etaExtBytes];
        byte[] com1 = scratchCom1;
        blc.commit(mseed, salt, xPacked, com1, key, x0, u0, u1);
        System.arraycopy(com1, 0, sig, com1Off, digestSize);

        // ComputePAlpha — alpha shares carry witness information (alpha1 is
        // serialized into sig and is then public, alpha0 only feeds com2);
        // allocated per call.
        byte[][] alpha0 = new byte[tau][etaExtBytes];
        byte[][] alpha1 = new byte[tau][etaExtBytes];
        piop.computePAlpha(com1, mseedEq, xPacked, x0, u0, u1, alpha0, alpha1);

        // com2 = Hash3(alpha0 || alpha1) AND serialize alpha1 into sig.
        // For our supported (base, ext) pairs the in-memory layout of an
        // eta-vector matches the wire layout exactly (alpha1Block bytes =
        // byteSizeFieldExt(eta)), so we can absorb alpha0[e] / alpha1[e]
        // directly and copy alpha1[e] into sig in one move — no per-iteration
        // throwaway buffer needed.
        byte[] com2 = scratchCom2;
        SHAKEDigest xof3 = sym.newXof();
        sym.xofUpdateTag(xof3, 3);
        for (int e = 0; e < tau; e++)
        {
            xof3.update(alpha0[e], 0, alpha1Block);
        }
        for (int e = 0; e < tau; e++)
        {
            xof3.update(alpha1[e], 0, alpha1Block);
            System.arraycopy(alpha1[e], 0, sig, serializedAlpha1Off + e * alpha1Block, alpha1Block);
        }
        sym.xofSqueeze(xof3, com2, 0, digestSize);
        System.arraycopy(com2, 0, sig, com2Off, digestSize);

        // hash = Hash4(pk, com1, com2, msg_hash) — pk == sk[0..pkSize]
        byte[] hash = scratchHash;
        SHAKEDigest xof4 = sym.newXof();
        sym.xofUpdateTag(xof4, 4);
        xof4.update(sk, 0, pkSize);
        xof4.update(com1, 0, digestSize);
        xof4.update(com2, 0, digestSize);
        xof4.update(msgHash, 0, digestSize);
        sym.xofSqueeze(xof4, hash, 0, digestSize);

        // SampleChallenge — writes 4-byte nonce directly into sig at nonceOff.
        int[] iStar = scratchIStar;
        sampleChallenge(hash, iStar, sig, nonceOff);

        // BLC.Open
        blc.open(key, iStar, sig, openingOff);

        return sig;
    }

    /* ============================ Verify ============================= */

    public boolean verify(byte[] pk, byte[] msg, byte[] sig)
    {
        if (pk.length != pkSize || sig.length != sigSize)
        {
            return false;
        }

        // pk = mseedEq (2*seedSize) || y; pass via offsets, no copies.
        int saltOff = 0;
        int com1Off = saltOff + saltSize;
        int com2Off = com1Off + digestSize;
        int serializedAlpha1Off = com2Off + digestSize;
        int alpha1Block = params.getByteSizeFieldBase(eta * params.getMu());
        int openingOff = serializedAlpha1Off + tau * alpha1Block;
        int nonceOff = sigSize - 4;

        byte[] msgHash = scratchMsgHash;
        SHAKEDigest xof = sym.newXof();
        sym.xofUpdateTag(xof, 2);
        xof.update(msg, 0, msg.length);
        sym.xofSqueeze(xof, msgHash, 0, digestSize);

        byte[] hash = scratchHash;
        SHAKEDigest xof4 = sym.newXof();
        sym.xofUpdateTag(xof4, 4);
        xof4.update(pk, 0, pkSize);
        xof4.update(sig, com1Off, digestSize);
        xof4.update(sig, com2Off, digestSize);
        xof4.update(msgHash, 0, digestSize);
        sym.xofSqueeze(xof4, hash, 0, digestSize);

        int[] iStar = scratchIStar;
        int tmpLen = scratchTmp.length;
        byte[] tmp = scratchTmp;
        SHAKEDigest xof5 = sym.newXof();
        sym.xofUpdateTag(xof5, 5);
        xof5.update(hash, 0, digestSize);
        xof5.update(sig, nonceOff, 4);
        sym.xofSqueeze(xof5, tmp, 0, tmpLen);
        for (int e = 0; e < tau; e++)
        {
            iStar[e] = ((tmp[2 * e] & 0xFF) + 256 * (tmp[2 * e + 1] & 0xFF)) & ((1 << nbEvalsLog) - 1);
        }
        int val = ((tmp[2 * tau] & 0xFF) + 256 * (tmp[2 * tau + 1] & 0xFF)) & ((1 << w) - 1);
        if (val != 0)
        {
            return false;
        }

        int nExtBytes = mqN * extBytesPerElt;
        int etaExtBytes = eta * extBytesPerElt;
        byte[][] xEval = new byte[tau][nExtBytes];
        byte[][] uEval = new byte[tau][etaExtBytes];
        // blc.eval still needs salt and com1 as byte[] (deeper signature change to take offsets).
        // The temporary slices here are small (saltSize + digestSize per verify)
        // and they only carry public information.
        byte[] salt = Arrays.copyOfRange(sig, saltOff, saltOff + saltSize);
        byte[] com1 = Arrays.copyOfRange(sig, com1Off, com1Off + digestSize);
        if (!blc.eval(salt, com1, sig, openingOff, iStar, xEval, uEval))
        {
            return false;
        }

        byte[][] alpha1 = new byte[tau][etaExtBytes];
        for (int e = 0; e < tau; e++)
        {
            // wire layout == in-memory layout for our supported (base, ext) pairs
            System.arraycopy(sig, serializedAlpha1Off + e * alpha1Block, alpha1[e], 0, alpha1Block);
        }
        byte[][] alpha0 = new byte[tau][etaExtBytes];
        // piop needs mseedEq and y as byte[]; mseedEq is pk[0..2*seedSize], y is pk[2*seedSize..].
        // Keep these as small slices for now — restructuring PIOP to take offsets is a deeper change.
        byte[] mseedEq = Arrays.copyOfRange(pk, 0, 2 * seedSize);
        byte[] y = Arrays.copyOfRange(pk, 2 * seedSize, pkSize);
        piop.recomputePAlpha(com1, mseedEq, y, iStar, xEval, uEval, alpha1, alpha0);

        byte[] com2Recomputed = scratchCom2;
        SHAKEDigest xof3 = sym.newXof();
        sym.xofUpdateTag(xof3, 3);
        for (int e = 0; e < tau; e++)
        {
            xof3.update(alpha0[e], 0, alpha1Block);
        }
        for (int e = 0; e < tau; e++)
        {
            xof3.update(sig, serializedAlpha1Off + e * alpha1Block, alpha1Block);
        }
        sym.xofSqueeze(xof3, com2Recomputed, 0, digestSize);

        // Constant-time compare against sig[com2Off..] directly.
        int diff = 0;
        for (int i = 0; i < digestSize; i++)
        {
            diff |= (com2Recomputed[i] ^ sig[com2Off + i]) & 0xFF;
        }
        return diff == 0;
    }

    private void sampleChallenge(byte[] hash, int[] iStar, byte[] sig, int nonceOff)
    {
        long nonceInt = 0;
        int tmpLen = scratchTmp.length;
        byte[] tmp = scratchTmp;
        for (;;)
        {
            sig[nonceOff    ] = (byte)(nonceInt & 0xFF);
            sig[nonceOff + 1] = (byte)((nonceInt >>> 8) & 0xFF);
            sig[nonceOff + 2] = (byte)((nonceInt >>> 16) & 0xFF);
            sig[nonceOff + 3] = (byte)((nonceInt >>> 24) & 0xFF);

            SHAKEDigest xof = sym.newXof();
            sym.xofUpdateTag(xof, 5);
            xof.update(hash, 0, digestSize);
            xof.update(sig, nonceOff, 4);
            sym.xofSqueeze(xof, tmp, 0, tmpLen);
            for (int e = 0; e < tau; e++)
            {
                iStar[e] = ((tmp[2 * e] & 0xFF) + 256 * (tmp[2 * e + 1] & 0xFF)) & ((1 << nbEvalsLog) - 1);
            }
            int val = ((tmp[2 * tau] & 0xFF) + 256 * (tmp[2 * tau + 1] & 0xFF)) & ((1 << w) - 1);
            if (val == 0)
            {
                return;
            }
            nonceInt++;
        }
    }
}
