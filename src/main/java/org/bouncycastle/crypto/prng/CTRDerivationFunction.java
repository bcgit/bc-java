package org.bouncycastle.crypto.prng;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class CTRDerivationFunction 
{
    private static final byte[] K_BITS = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    private BlockCipher _underlyingCipher;
    private int         _seedLength;
    private int         _keySizeInBits;

    public CTRDerivationFunction(BlockCipher underlyingCipher, int keySizeInBits, int seedLength) 
    {
        _underlyingCipher = underlyingCipher;
        _seedLength = seedLength;
        _keySizeInBits = keySizeInBits;
    }

    public int getSeedlength()
    {
        return _seedLength;
    }

    public int getSecurityStrength()
    {
        return _underlyingCipher.getBlockSize()*8;
    }

    public byte[] getBytes(byte[] input)
    {
        // TODO:
        //_underlyingCipher.update(input, 0, input.length);
        byte[] K = new byte[_keySizeInBits / 8];
        System.arraycopy(K_BITS, 0, K, 0, K.length); 
        _underlyingCipher.init(true, new KeyParameter(K));
        byte[] out = new byte[_underlyingCipher.getBlockSize()];
        _underlyingCipher.processBlock(input, 0, out, 0);
        return out;
    }

    public byte[] getDFBytes(byte[] seedMaterial, int seedLength)
    {
        return cipherDFProcess(_underlyingCipher, seedLength, seedMaterial);
    }

    // 1. If (number_of_bits_to_return > max_number_of_bits), then return an
    // ERROR_FLAG.
    // 2. L = len (input_string)/8.
    // 3. N = number_of_bits_to_return/8.
    // Comment: L is the bitstring represention of
    // the integer resulting from len (input_string)/8.
    // L shall be represented as a 32-bit integer.
    //
    // Comment : N is the bitstring represention of
    // the integer resulting from
    // number_of_bits_to_return/8. N shall be
    // represented as a 32-bit integer.
    //
    // 4. S = L || N || input_string || 0x80.
    // 5. While (len (S) mod outlen)
    // Comment : Pad S with zeros, if necessary.
    // 0, S = S || 0x00.
    //
    // Comment : Compute the starting value.
    // 6. temp = the Null string.
    // 7. i = 0.
    // 8. K = Leftmost keylen bits of 0x00010203...1D1E1F.
    // 9. While len (temp) < keylen + outlen, do
    //
    // IV = i || 0outlen - len (i).
    //
    // 9.1
    //
    // temp = temp || BCC (K, (IV || S)).
    //
    // 9.2
    //
    // i = i + 1.
    //
    // 9.3
    //
    // Comment : i shall be represented as a 32-bit
    // integer, i.e., len (i) = 32.
    //
    // Comment: The 32-bit integer represenation of
    // i is padded with zeros to outlen bits.
    //
    // Comment: Compute the requested number of
    // bits.
    //
    // 10. K = Leftmost keylen bits of temp.
    //
    // 11. X = Next outlen bits of temp.
    //
    // 12. temp = the Null string.
    //
    // 13. While len (temp) < number_of_bits_to_return, do
    //
    // 13.1 X = Block_Encrypt (K, X).
    //
    // 13.2 temp = temp || X.
    //
    // 14. requested_bits = Leftmost number_of_bits_to_return of temp.
    //
    // 15. Return SUCCESS and requested_bits.
    private byte[] cipherDFProcess(BlockCipher engine, int bitLength, byte[] inputString)
    {
        int outLen = engine.getBlockSize();
        int L = inputString.length; // already in bytes
        int N = bitLength / 8;
        // 4 S = L || N || inputstring || 0x80
        int sLen = 4 + 4 + L + 1;
        int blockLen = ((sLen + outLen - 1) / outLen) * outLen;
        byte[] S = new byte[blockLen];
        copyIntToByteArray(S, L, 0);
        copyIntToByteArray(S, N, 4);
        System.arraycopy(inputString, 0, S, 8, L);
        S[8 + L] = (byte)0x80;
        // S already padded with zeros
        
        byte[] temp = new byte[N+L];
        byte[] bccOut = new byte[outLen];

        byte[] IV = new byte[outLen]; 
        
        int i = 0;
        byte[] K = new byte[_keySizeInBits / 8];
        System.arraycopy(K_BITS, 0, K, 0, K.length); 
        while (i*outLen*8 < _keySizeInBits + outLen *8)
        {
            copyIntToByteArray(IV, i, 0);
            BCC(bccOut, K, IV, S);

            int bytesToCopy = ((temp.length - i * outLen) > outLen)
                    ? outLen
                    : (temp.length - i * outLen);
            
            System.arraycopy(bccOut, 0, temp, i * outLen, bytesToCopy);
            ++i;
        }
        return temp;
    }

    
    /*
    * 1. chaining_value = 0^outlen    
    *    . Comment: Set the first chaining value to outlen zeros.
    * 2. n = len (data)/outlen.
    * 3. Starting with the leftmost bits of data, split the data into n blocks of outlen bits 
    *    each, forming block(1) to block(n). 
    * 4. For i = 1 to n do
    * 4.1 input_block = chaining_value ^ block(i) .
    * 4.2 chaining_value = Block_Encrypt (Key, input_block).
    * 5. output_block = chaining_value.
    * 6. Return output_block. 
     */
    private void BCC(byte[] bccOut, byte[] k, byte[] iV, byte[] data)
    {
        int outlen = _underlyingCipher.getBlockSize();
        byte[] chainingValue = new byte[outlen]; // initial values = 0
        int n = data.length / outlen;
        
        byte[] inputBlock = new byte[outlen];
        _underlyingCipher.init(true, new KeyParameter(k));
        for (int i=0; i< n; i++) 
        {
            XOR(inputBlock, chainingValue, data, i*outlen);
            _underlyingCipher.processBlock(inputBlock, 0, chainingValue, 0);
        }
        System.arraycopy(chainingValue, 0, bccOut, 0, bccOut.length);
    }
    
    private void XOR(byte[] out, byte[] a, byte[] b, int bOff)
    {
        for (int i=0; i< out.length; i++) 
        {
            out[i] = (byte)(a[i] ^ b[i+bOff]);
        }
    }

    private void copyIntToByteArray(byte[] buf, int value, int offSet)
    {
        buf[offSet + 0] = ((byte)(value >> 24));
        buf[offSet + 1] = ((byte)(value >> 16));
        buf[offSet + 2] = ((byte)(value >> 8));
        buf[offSet + 3] = ((byte)(value));
    }

    public byte[] getByteGen(byte[] input, int length)
    {
        // TODO:
        // return byteGenProcess(_underlyingCipher, input, length);
        return null;
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

    public int getEngineBlockSize()
    {
        return _underlyingCipher.getBlockSize();
    }

    public BlockCipher getEngine()
    {
        return _underlyingCipher;
    }
}
