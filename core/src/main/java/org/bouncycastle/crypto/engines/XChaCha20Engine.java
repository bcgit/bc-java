package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Pack;

/**
 * Implementation of the XChaCha20 stream cipher (extended-nonce ChaCha20)
 * as described in draft-irtf-cfrg-xchacha-03.
 * <p>
 * XChaCha20 takes a 256 bit key and a 192 bit nonce. The first 128 bits of
 * the nonce are used together with the key in HChaCha20 to derive a 256 bit
 * subkey; that subkey, together with the remaining 64 bits of the nonce
 * (prefixed by four zero bytes to form a 96 bit IETF nonce), then drives a
 * standard ChaCha20-IETF stream as defined by RFC 7539.
 */
public class XChaCha20Engine
    extends ChaCha7539Engine
{
    public XChaCha20Engine()
    {
        super();
    }

    public String getAlgorithmName()
    {
        return "XChaCha20";
    }

    protected int getNonceSize()
    {
        return 24;
    }

    protected void setKey(byte[] keyBytes, byte[] ivBytes)
    {
        if (keyBytes == null)
        {
            throw new IllegalArgumentException(getAlgorithmName() + " doesn't support re-init with null key");
        }

        if (keyBytes.length != 32)
        {
            throw new IllegalArgumentException(getAlgorithmName() + " requires a 256 bit key");
        }

        // HChaCha20(key, nonce[0..15]) -> 256 bit subkey. Build the input
        // state in a scratch array so engineState can be initialised
        // directly to the ChaCha20-IETF state in the second phase.
        int[] hcInput = new int[16];
        packTauOrSigma(keyBytes.length, hcInput, 0);
        Pack.littleEndianToInt(keyBytes, 0, hcInput, 4, 8);
        Pack.littleEndianToInt(ivBytes, 0, hcInput, 12, 4);

        int[] hcOut = new int[16];
        ChaChaEngine.chachaCore(20, hcInput, hcOut);

        // chachaCore performs the final addition; HChaCha20 is the round
        // function only, so subtract the input back out. The HChaCha20
        // subkey is the un-added words 0..3 || 12..15 (32 bytes).

        // Set up the ChaCha20-IETF state used for keystream generation:
        // [0..3]  = constants
        // [4..11] = HChaCha20 subkey
        // [12]    = 32 bit counter (zeroed by reset())
        // [13..15] = 96 bit nonce = 0x00000000 || ivBytes[16..23]
        packTauOrSigma(32, engineState, 0);
        engineState[4] = hcOut[0] - hcInput[0];
        engineState[5] = hcOut[1] - hcInput[1];
        engineState[6] = hcOut[2] - hcInput[2];
        engineState[7] = hcOut[3] - hcInput[3];
        engineState[8] = hcOut[12] - hcInput[12];
        engineState[9] = hcOut[13] - hcInput[13];
        engineState[10] = hcOut[14] - hcInput[14];
        engineState[11] = hcOut[15] - hcInput[15];

        engineState[13] = 0;
        Pack.littleEndianToInt(ivBytes, 16, engineState, 14, 2);
    }
}
