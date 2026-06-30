package org.bouncycastle.pqc.crypto.faest;

/**
 * FAEST v2.0 "extend witness": pack the AES intermediate state into the
 * proof-input byte vector the VOLE-AES prover commits to.
 * <p>
 * The packed witness has the following layout (matching the spec / the
 * reference implementation):
 * <ul>
 *   <li><b>Key-schedule prefix</b> ({@code Lke} bits, faest-ref aes.c:472):
 *       <ul>
 *         <li>FAEST mode: the first {@code nk} columns (the key itself) plus
 *             {@code S_ke / 4} columns selected from the schedule at stride
 *             4 (for &lambda; &isin; {128, 256}) or 6 (&lambda; = 192).</li>
 *         <li>FAEST-EM mode: the OWF secret key verbatim
 *             ({@code λ / 8} bytes).</li>
 *       </ul>
 *   </li>
 *   <li><b>Per-block AES trace</b> ({@code beta} blocks):
 *       <ul>
 *         <li>For each middle round {@code r} (1 &le; r &lt; numRounds):
 *             <ul>
 *               <li>If {@code r} is <em>odd</em>: emit
 *                   {@link FaestAES#invnorm} nibbles of consecutive byte
 *                   pairs of the pre-SubBytes state ({@code blockWords * 2}
 *                   bytes).</li>
 *               <li>Then apply SubBytes &amp; ShiftRows.</li>
 *               <li>If {@code r} is <em>even</em>: emit the raw state
 *                   ({@code blockWords * 4} bytes).</li>
 *               <li>Then apply MixColumns &amp; AddRoundKey.</li>
 *             </ul>
 *         </li>
 *         <li>The final round is not stored.</li>
 *       </ul>
 *   </li>
 * </ul>
 * Total output length is {@code params.getEll() / 8} bytes (the prover's
 * witness {@code w}).
 * <p>
 * In FAEST-EM mode {@code key} and {@code in} are swapped at the start:
 * the OWF is {@code AES(input).encrypt(key) XOR key}, so the AES round
 * function is keyed by {@code input}.
 * <p>
 * Source of truth: {@code aes_extend_witness}, aes.c:411.
 */
final class AesWitnessExtension
{
    private AesWitnessExtension()
    {
    }

    /**
     * Produce the packed witness for the given {@code (key, in)} pair under
     * the supplied parameter set. Output length is {@code params.getEll() / 8}.
     */
    static byte[] extendWitness(byte[] key, byte[] in, FaestParameters params)
    {
        final int lambda = params.getLambda();
        final int ell = params.getEll();
        final int Ske = params.getSke();
        final int numRounds = params.getR();
        final int nk = lambda / 32;
        final int Lke = params.getLke();
        final int beta = params.getBeta();

        int blockWords;
        if (params == FaestParameters.faest_em_192s || params == FaestParameters.faest_em_192f)
        {
            blockWords = FaestAES.RIJNDAEL_BLOCK_WORDS_192;
        }
        else if (params == FaestParameters.faest_em_256s || params == FaestParameters.faest_em_256f)
        {
            blockWords = FaestAES.RIJNDAEL_BLOCK_WORDS_256;
        }
        else
        {
            blockWords = FaestAES.AES_BLOCK_WORDS;
        }

        // EM mode: key and input swap roles. The AES round function gets keyed
        // by what the caller passed as `in`, and `key` becomes the plaintext.
        byte[] aesKey, aesIn;
        if (params.isEm())
        {
            aesKey = in;
            aesIn  = key;
        }
        else
        {
            aesKey = key;
            aesIn  = in;
        }

        // Expand the round-key schedule.
        int keyWords = lambda / 32;
        byte[] roundKeys = new byte[(numRounds + 1) * blockWords * 4];
        FaestAES.expandKey(roundKeys, aesKey, 0, keyWords, blockWords, numRounds);

        byte[] w = new byte[(ell + 7) >>> 3];
        int wOff = 0;

        // Key-schedule prefix.
        if (!params.isEm())
        {
            // First nk columns = the original key bytes (already at the start of roundKeys).
            for (int i = 0; i < nk; ++i)
            {
                System.arraycopy(roundKeys, i * 4, w, wOff, 4);
                wOff += 4;
            }
            // Then S_ke/4 selected columns from the rest of the schedule.
            int stride = (lambda == 192) ? 6 : 4;
            int ik = nk;
            for (int j = 0; j < Ske / 4; ++j)
            {
                System.arraycopy(roundKeys, ik * 4, w, wOff, 4);
                wOff += 4;
                ik += stride;
            }
        }
        else
        {
            // EM mode: store the OWF secret key (= post-swap `aesIn` = pre-swap `key`).
            System.arraycopy(aesIn, 0, w, wOff, lambda / 8);
            wOff += lambda / 8;
        }

        if (wOff != Lke / 8)
        {
            throw new IllegalStateException(
                "key-schedule prefix length mismatch: expected " + (Lke / 8) + ", got " + wOff);
        }

        // First block (always present).
        wOff += emitBlockTrace(w, wOff, aesIn, 0, roundKeys, blockWords, numRounds);

        // beta = 2 only for non-EM AES-192 / AES-256: second block with in[0] XOR 0x01.
        if (beta == 2)
        {
            byte[] buf = new byte[16];
            System.arraycopy(aesIn, 0, buf, 0, 16);
            buf[0] = (byte)(buf[0] ^ 0x01);
            wOff += emitBlockTrace(w, wOff, buf, 0, roundKeys, blockWords, numRounds);
        }

        if (wOff != ell / 8)
        {
            throw new IllegalStateException(
                "total witness length mismatch: expected " + (ell / 8) + ", got " + wOff);
        }
        return w;
    }

    /**
     * Run one AES encryption block-by-block, interleaving witness writes per
     * the spec: invnorm-nibble pairs on odd rounds (before SubBytes), raw
     * state on even rounds (after SubBytes+ShiftRows). Returns bytes written.
     */
    private static int emitBlockTrace(byte[] w, int wOff,
                                       byte[] in, int inOff,
                                       byte[] roundKeys, int blockWords, int numRounds)
    {
        int start = wOff;
        byte[] state = new byte[blockWords * 4];
        System.arraycopy(in, inOff, state, 0, blockWords * 4);

        FaestAES.addRoundKey(state, roundKeys, 0, blockWords);

        for (int round = 1; round < numRounds; ++round)
        {
            if ((round & 1) == 1)
            {
                wOff += FaestAES.storeInvnormState(w, wOff, state, blockWords);
            }
            FaestAES.subBytes(state, blockWords);
            FaestAES.shiftRow(state, blockWords);
            if ((round & 1) == 0)
            {
                wOff += FaestAES.storeState(w, wOff, state, blockWords);
            }
            FaestAES.mixColumn(state, blockWords);
            FaestAES.addRoundKey(state, roundKeys, round, blockWords);
        }
        return wOff - start;
    }
}
