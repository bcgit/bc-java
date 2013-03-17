package org.bouncycastle.crypto.prng;

import org.bouncycastle.crypto.Digest;

public class HashDerivationFunction implements DRBGDerivationFunction
{

    private Digest _underlyingDigest;
    private int    _seedLength;

    public HashDerivationFunction(Digest underlyingDigest, int seedLength)
    {
        _underlyingDigest = underlyingDigest;
        _seedLength = seedLength;
    }

    public int getSeedlength()
    {
        return _seedLength;
    }

    public int getSecurityStrength()
    {
        return 128;
    }

    public byte[] getBytes(byte[] input)
    {
        _underlyingDigest.update(input, 0, input.length);
        byte[] hash = new byte[_underlyingDigest.getDigestSize()];
        _underlyingDigest.doFinal(hash, 0);
        return hash;
    }

    public byte[] getDFBytes(byte[] seedMaterial, int seedLength)
    {
        return hashDFProcess(_underlyingDigest, seedLength, seedMaterial);
    }

    // 1. temp = the Null string.
    // 2. .
    // 3. counter = an 8-bit binary value representing the integer "1".
    // 4. For i = 1 to len do
    // Comment : In step 4.1, no_of_bits_to_return
    // is used as a 32-bit string.
    // 4.1 temp = temp || Hash (counter || no_of_bits_to_return ||
    // input_string).
    // 4.2 counter = counter + 1.
    // 5. requested_bits = Leftmost (no_of_bits_to_return) of temp.
    // 6. Return SUCCESS and requested_bits.
    private byte[] hashDFProcess(Digest digest, int bitLength, byte[] inputString)
    {
        byte[] temp = new byte[bitLength / 8];

        int len = temp.length / digest.getDigestSize();
        int counter = 1;

        byte[] dig = new byte[digest.getDigestSize()];

        for (int i = 0; i <= len; i++)
        {
            digest.update((byte)counter);

            digest.update((byte)(bitLength >> 24));
            digest.update((byte)(bitLength >> 16));
            digest.update((byte)(bitLength >> 8));
            digest.update((byte)bitLength);

            digest.update(inputString, 0, inputString.length);

            digest.doFinal(dig, 0);

            int bytesToCopy = ((temp.length - i * dig.length) > dig.length)
                    ? dig.length
                    : (temp.length - i * dig.length);
            System.arraycopy(dig, 0, temp, i * dig.length, bytesToCopy);

            counter++;
        }

        return temp;
    }

    public byte[] getByteGen(byte[] input, int length)
    {
        return byteGenProcess(_underlyingDigest, input, length);
    }

    // 1. m = [requested_number_of_bits / outlen]
    // 2. data = V.
    // 3. W = the Null string.
    // 4. For i = 1 to m
    // 4.1 wi = Hash (data).
    // 4.2 W = W || wi.
    // 4.3 data = (data + 1) mod 2^seedlen
    // .
    // 5. returned_bits = Leftmost (requested_no_of_bits) bits of W.
    private byte[] byteGenProcess(Digest digest, byte[] input, int lengthInBits)
    {
        int m = (lengthInBits / 8) / digest.getDigestSize();

        byte[] data = new byte[input.length];
        System.arraycopy(input, 0, data, 0, input.length);

        byte[] W = new byte[lengthInBits / 8];

        byte[] dig = new byte[digest.getDigestSize()];

        for (int i = 0; i <= m; i++)
        {
            digest.update(data, 0, data.length);

            digest.doFinal(dig, 0);

            int bytesToCopy = ((W.length - i * dig.length) > dig.length)
                    ? dig.length
                    : (W.length - i * dig.length);
            System.arraycopy(dig, 0, W, i * dig.length, bytesToCopy);

            addOneTo(data);
        }

        return W;
    }

    private void addOneTo(byte[] longer)
    {
        int carry = 1;
        for (int i = 1; i <= longer.length; i++) // warning
        {
            int res = (longer[longer.length - i] & 0xff) + carry;
            carry = (res > 0xff) ? 1 : 0;
            longer[longer.length - i] = (byte)res;
        }
    }

}
