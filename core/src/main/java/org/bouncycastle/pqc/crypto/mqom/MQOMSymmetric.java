package org.bouncycastle.pqc.crypto.mqom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Symmetric primitives for MQOM v2.1: block-cipher Enc, XOF, TweakSalt,
 * LinOrtho, SeedDerive, SeedCommit and PRG. Selects the right pair of
 * primitives for the security level:
 *
 * <pre>
 *   lambda  Enc                         XOF
 *   128     AES-128                     SHAKE-128
 *   192     Rijndael-256-256 truncated  SHAKE-256
 *   256     Rijndael-256-256            SHAKE-256
 * </pre>
 *
 * <p>For lambda = 192 the Enc primitive is defined as
 * <code>Truncate_192(Enc_256(key || 0^64, ptx || 0^64))</code> -- the input
 * key and plaintext are zero-padded to 32 bytes, the ciphertext is
 * truncated back to 24 bytes.
 *
 * <p>Cipher contexts (key-scheduled engines) are returned as opaque
 * {@code Object}s; pass them back through {@link #encEncrypt} /
 * {@link #seedDerive} / {@link #seedCommit} unchanged.
 *
 * <p>Instances are NOT thread-safe — scratch buffers are reused across the
 * symmetric subroutines. {@link MQOMEngine} owns one symmetric instance per
 * engine, and engines are not shared across threads (each
 * {@code MQOMEngine.getInstance} call constructs a fresh one).
 */
final class MQOMSymmetric
{
    private final MQOMParameters params;
    private final int seedSize;
    private final int saltSize;
    private final int digestSize;
    private final int securityBits;

    // Per-instance scratch reused across hot-path calls. See class-level
    // thread-safety note above.
    //
    // Only buffers holding *public* derivatives are kept as instance scratch;
    // sensitive ones (linortho applied to secret seeds, Cat3 plaintext / ciphertext
    // pad blocks) are allocated per-call so witness-derived material does not
    // outlive a single primitive invocation.
    private final byte[] scratchKey;
    private final byte[] scratchTweakedSalt;

    MQOMSymmetric(MQOMParameters params)
    {
        this.params = params;
        this.seedSize = params.getSeedSize();
        this.saltSize = params.getSaltSize();
        this.digestSize = params.getDigestSize();
        this.securityBits = params.getSecurityBits();
        int blockBytes = (securityBits == 128) ? 16 : 32;
        this.scratchKey = new byte[blockBytes];
        this.scratchTweakedSalt = new byte[saltSize];
    }

    int getSeedSize()
    {
        return seedSize;
    }

    int getSaltSize()
    {
        return saltSize;
    }

    int getDigestSize()
    {
        return digestSize;
    }

    MQOMParameters getParameters()
    {
        return params;
    }

    /* ============================ XOF ================================ */

    SHAKEDigest newXof()
    {
        return new SHAKEDigest((securityBits == 128) ? 128 : 256);
    }

    void xofUpdateTag(SHAKEDigest xof, int tag)
    {
        xof.update((byte)(tag & 0xFF));
    }

    void xofSqueeze(SHAKEDigest xof, byte[] out, int outOff, int len)
    {
        xof.doFinal(out, outOff, len);
    }

    /* ============================ TweakSalt ========================== */

    void tweakSalt(byte[] salt, byte[] tweakedSalt, int sel, int e, int j)
    {
        System.arraycopy(salt, 0, tweakedSalt, 0, saltSize);
        tweakedSalt[0] ^= (byte)((sel + 4 * e) & 0xFF);
        tweakedSalt[1] ^= (byte)(j & 0xFF);
        tweakedSalt[2] ^= (byte)((j >>> 8) & 0xFF);
    }

    /* ============================ LinOrtho =========================== */

    void linOrtho(byte[] seed, int seedOff, byte[] out, int outOff)
    {
        int h = seedSize / 2;
        for (int i = 0; i < h; i++)
        {
            out[outOff + i] = (byte)((seed[seedOff + h + i] ^ seed[seedOff + i]) & 0xFF);
        }
        for (int i = 0; i < h; i++)
        {
            out[outOff + h + i] = seed[seedOff + i];
        }
    }

    /* ============================ Enc ================================ */

    /**
     * Schedule a fresh cipher context from the given seedSize-byte key.
     * The key bytes are read into a reusable scratch buffer; BC's AES /
     * Rijndael engines copy the key into their internal round-key tables on
     * {@code init()}, so the scratch buffer is safe to reuse on the next call.
     */
    Object encKeySched(byte[] key, int keyOff)
    {
        System.arraycopy(key, keyOff, scratchKey, 0, seedSize);
        if (securityBits != 128 && seedSize < scratchKey.length)
        {
            // Zero-pad Cat3's 24-byte key out to the 32-byte Rijndael block.
            for (int i = seedSize; i < scratchKey.length; i++)
            {
                scratchKey[i] = 0;
            }
        }
        BlockCipher engine = (securityBits == 128)
            ? (BlockCipher)AESEngine.newInstance()
            : new RijndaelEngine(256);
        engine.init(true, new KeyParameter(scratchKey));
        return engine;
    }

    /**
     * Encrypt one seedSize-byte block under the keyed context. For lambda = 192
     * the input is zero-padded to 32 bytes, encrypted with Rijndael-256-256,
     * and the output is truncated to 24 bytes (reusing instance scratch).
     */
    void encEncrypt(Object ctx, byte[] pt, int ptOff, byte[] ct, int ctOff)
    {
        if (securityBits != 192)
        {
            ((BlockCipher)ctx).processBlock(pt, ptOff, ct, ctOff);
            return;
        }
        // securityBits == 192: pad-encrypt-truncate.
        //
        // padPt holds the secret plaintext block (a witness-derived seed for the
        // most common callers) so it is allocated per call rather than reused as
        // instance scratch — the buffer dies with the stack frame and does not
        // linger in the engine's heap state.
        byte[] padPt = new byte[32];
        byte[] padCt = new byte[32];
        System.arraycopy(pt, ptOff, padPt, 0, 24);
        ((BlockCipher)ctx).processBlock(padPt, 0, padCt, 0);
        System.arraycopy(padCt, 0, ct, ctOff, 24);
    }

    /* ============================ SeedDerive ========================= */

    void seedDerive(Object ctx, byte[] seed, int seedOff, byte[] out, int outOff)
    {
        // linortho holds a permutation of the (secret) seed bytes — allocate
        // per-call so it does not survive in the engine's heap state.
        byte[] linortho = new byte[seedSize];
        linOrtho(seed, seedOff, linortho, 0);
        encEncrypt(ctx, seed, seedOff, out, outOff);
        for (int i = 0; i < seedSize; i++)
        {
            out[outOff + i] = (byte)((out[outOff + i] ^ linortho[i]) & 0xFF);
        }
    }

    /* ============================ SeedCommit ========================= */

    void seedCommit(byte[] salt, int e, byte[] seed, int seedOff, byte[] out, int outOff)
    {
        // Stand-alone form: schedule two contexts here. Used only by callers
        // that don't keep their own per-execution context pair (currently none).
        byte[] tweakedSalt1 = new byte[saltSize];
        tweakSalt(salt, tweakedSalt1, 0, e, 0);
        byte[] tweakedSalt2 = new byte[saltSize];
        System.arraycopy(tweakedSalt1, 0, tweakedSalt2, 0, saltSize);
        tweakedSalt2[0] ^= 0x01;
        Object ctx1 = encKeySched(tweakedSalt1, 0);
        Object ctx2 = encKeySched(tweakedSalt2, 0);
        seedCommit(ctx1, ctx2, seed, seedOff, out, outOff);
    }

    void seedCommit(Object ctx1, Object ctx2, byte[] seed, int seedOff, byte[] out, int outOff)
    {
        byte[] linortho = new byte[seedSize];
        linOrtho(seed, seedOff, linortho, 0);
        encEncrypt(ctx1, seed, seedOff, out, outOff);
        for (int i = 0; i < seedSize; i++)
        {
            out[outOff + i] = (byte)((out[outOff + i] ^ linortho[i]) & 0xFF);
        }
        encEncrypt(ctx2, seed, seedOff, out, outOff + seedSize);
        for (int i = 0; i < seedSize; i++)
        {
            out[outOff + seedSize + i] = (byte)((out[outOff + seedSize + i] ^ linortho[i]) & 0xFF);
        }
    }

    /* ============================ PRG ================================ */

    void prg(byte[] salt, int e, byte[] seed, int seedOff, int nbytes, byte[] out, int outOff)
    {
        byte[] linortho = new byte[seedSize];
        linOrtho(seed, seedOff, linortho, 0);

        int nblocks = nbytes / seedSize;
        int idx = 0;
        for (int i = 0; i < nblocks; i++)
        {
            tweakSalt(salt, scratchTweakedSalt, 3, e, i);
            Object engine = encKeySched(scratchTweakedSalt, 0);
            encEncrypt(engine, seed, seedOff, out, outOff + idx);
            for (int k = 0; k < seedSize; k++)
            {
                out[outOff + idx + k] = (byte)((out[outOff + idx + k] ^ linortho[k]) & 0xFF);
            }
            idx += seedSize;
        }
        int rem = nbytes - nblocks * seedSize;
        if (rem != 0)
        {
            tweakSalt(salt, scratchTweakedSalt, 3, e, nblocks);
            Object engine = encKeySched(scratchTweakedSalt, 0);
            byte[] block = new byte[seedSize];
            encEncrypt(engine, seed, seedOff, block, 0);
            for (int k = 0; k < seedSize; k++)
            {
                block[k] = (byte)((block[k] ^ linortho[k]) & 0xFF);
            }
            System.arraycopy(block, 0, out, outOff + idx, rem);
        }
    }
}
