package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Pack;

/**
 * Implementation of eXtended Nonce ChaCha (XChaCha20).
 *
 * The implementation follows the IETF Draft for XChaCha20-Poly1305
 * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha
 *
 * XChaCha20 requires a 256bit key and a 192bit IV.
 */
public class XChaCha20Engine extends ChaChaEngine
{

    /**
     * Create a new XChaCha20 engine.
     */
    public XChaCha20Engine()
    {
        super();
    }

    @Override
    public String getAlgorithmName()
    {
        return "XChaCha20";
    }

    @Override
    protected int getNonceSize()
    {
        return 24;
    }

    @Override
    protected void setKey(byte[] keyBytes, byte[] ivBytes)
    {
        if (keyBytes == null)
        {
            throw new IllegalArgumentException(
                getAlgorithmName() + " doesn't support re-init with null key");
        }

        if (keyBytes.length != 32)
        {
            throw new IllegalStateException(getAlgorithmName() + " requires a 256 bit key");
        }

        // Derive sub key using the HChaCha algorithm and set copy it to the engine state
        int[] subKey = hChaChaDeriveSubKey(keyBytes, ivBytes);
        System.arraycopy(subKey, 0, engineState, 4, subKey.length);

        // Use last 64 bits of input IV as nonce for ChaCha20
        Pack.littleEndianToInt(ivBytes, 16, engineState, 14, 2);
    }

    public int[] hChaChaDeriveSubKey(byte[] keyBytes, byte[] ivBytes)
    {
        if (keyBytes == null)
        {
            throw new IllegalArgumentException("HChaCha" + rounds + " doesn't support null keys");
        }

        if (keyBytes.length != 32)
        {
            throw new IllegalStateException("HChaCha" + rounds + "  requires a 256 bit key");
        }

        if (ivBytes == null)
        {
            throw new IllegalArgumentException("HChaCha" + rounds + "  needs a non-null IV");
        }

        if (ivBytes.length < 16)
        {
            throw new IllegalArgumentException(
                "HChaCha" + rounds + " needs an at least 128 bit nonce");
        }

        // Set key for HChaCha20
        super.setKey(keyBytes, ivBytes);
        Pack.littleEndianToInt(ivBytes, 0, engineState, 12, 4);

        // Process engine state to generate ChaCha20 key
        int[] hchacha20Out = new int[engineState.length];
        chachaCore(20, engineState, hchacha20Out);

        // Take first and last 128 bits of output as the sub key
        int[] subkey = new int[8];
        System.arraycopy(hchacha20Out, 0, subkey, 0, 4);
        System.arraycopy(hchacha20Out, 12, subkey, 4, 4);

        // Remove addition in final round of chachaCore
        subkey[0] -= engineState[0];
        subkey[1] -= engineState[1];
        subkey[2] -= engineState[2];
        subkey[3] -= engineState[3];
        subkey[4] -= engineState[12];
        subkey[5] -= engineState[13];
        subkey[6] -= engineState[14];
        subkey[7] -= engineState[15];

        return subkey;
    }
}
