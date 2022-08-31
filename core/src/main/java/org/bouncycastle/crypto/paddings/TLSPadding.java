package org.bouncycastle.crypto.paddings;

import org.bouncycastle.crypto.InvalidCipherTextException;

import java.security.SecureRandom;

public class TLSPadding implements BlockCipherPadding {

    public void init(SecureRandom random) throws IllegalArgumentException {

    }

    public String getPaddingName() {
        return "TLS";
    }

    public int addPadding(byte[] in, int inOff) {

        byte code = (byte) (in.length - inOff - 1);

        while (inOff < in.length) {
            in[inOff] = code;
            inOff++;
        }

        return code + 1;
    }

    public int padCount(byte[] in) throws InvalidCipherTextException {

        byte lastByte = in[in.length - 1];
        int count = (lastByte & 0xFF) + 1;
        int position = in.length - count;

        int failed = (position | (count - 1)) >> 31;
        for (int i = 0; i < in.length; ++i) {
            failed |= (in[i] ^ lastByte) & ~((i - position) >> 31);
        }
        if (failed != 0) {
            throw new InvalidCipherTextException("pad block corrupted");
        }

        return count;
    }
}
