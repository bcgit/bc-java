package org.bouncycastle.crypto.prng;

import javax.crypto.Cipher;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class CTRSP800DRBG
{
    private EntropySource         _entropySource;
    private BlockCipher           _engine;
    private int                   _keySizeInBits;
    private int                   _seedLength;
    
    // internal state
    private byte[]                _Key;
    private byte[]                _V;
    private int                   _reseedCounter;

    public CTRSP800DRBG(BlockCipher engine, int keySizeInBits, int seedLength, EntropySource entropySource, byte[] nonce,
            byte[] personalisationString, int securityStrength)
    {

        _entropySource = entropySource;
        _engine = engine;
        
        _keySizeInBits = keySizeInBits;
        _seedLength = seedLength;

        int entropyLengthInBytes = securityStrength;
        byte[] entropy = entropySource.getEntropy(entropyLengthInBytes / 8);

        System.out.println("Constructor Entropy: " + new String(Hex.encode(entropy)));

        byte[] seedMaterial = new byte[entropy.length + nonce.length + personalisationString.length];

        System.arraycopy(entropy, 0, seedMaterial, 0, entropy.length);
        System.arraycopy(nonce, 0, seedMaterial, entropy.length, nonce.length);
        System.arraycopy(personalisationString, 0, seedMaterial, entropy.length + nonce.length,
                personalisationString.length);

        System.out.println("Constructor SeedMaterial: " + new String(Hex.encode(seedMaterial)));

        byte[] seed = getDFBytes(seedMaterial, _seedLength);

        System.out.println("Constructor Seed: " + new String(Hex.encode(seed)));

        int outlen = engine.getBlockSize();
        _Key = new byte[outlen];
        _V = new byte[outlen];

        CTR_DRBG_Update(seed, _Key, _V); // _Key & _V are modified by this call

        System.out.println("Constructor V  : " + new String(Hex.encode(_V)));
        System.out.println("Constructor Key: " + new String(Hex.encode(_Key)));

    }

    private void CTR_DRBG_Update(byte[] seed, byte[] key, byte[] v)
    {
        byte[] temp = new byte[seed.length];
        byte[] outputBlock = new byte[seed.length];
        
        int i=0;
        int outLen = _engine.getBlockSize();

        _engine.init(true, new KeyParameter(key));
        while (i*outLen < seed.length)
        {
            addOneTo(v);
            _engine.processBlock(v, 0, outputBlock, 0);

            int bytesToCopy = ((temp.length - i * outLen) > outLen)
                    ? outLen
                    : (temp.length - i * outLen);
            
            System.arraycopy(outputBlock, 0, temp, i * outLen, bytesToCopy);
            ++i;
        }
        
        XOR(temp, temp, seed, 0);
        
        System.arraycopy(temp, 0, key, 0, key.length);
        System.arraycopy(temp, temp.length-outLen-1, v, 0, outLen);
    }
    
    private void XOR(byte[] out, byte[] a, byte[] b, int bOff)
    {
        for (int i=0; i< out.length; i++) 
        {
            out[i] = (byte)(a[i] ^ b[i+bOff]);
        }
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
    
    // -- Internal state migration ---
    // TODO; clean up after
    
    private static final byte[] K_BITS = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    
    private byte[] getBytes(byte[] input)
    {
        // TODO:
        //_underlyingCipher.update(input, 0, input.length);
        byte[] K = new byte[_keySizeInBits / 8];
        System.arraycopy(K_BITS, 0, K, 0, K.length); 
        _engine.init(true, new KeyParameter(K));
        byte[] out = new byte[_engine.getBlockSize()];
        _engine.processBlock(input, 0, out, 0);
        return out;
    }

    private byte[] getDFBytes(byte[] seedMaterial, int seedLength)
    {
        return cipherDFProcess(_engine, seedLength, seedMaterial);
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
        int outlen = _engine.getBlockSize();
        byte[] chainingValue = new byte[outlen]; // initial values = 0
        int n = data.length / outlen;
        
        byte[] inputBlock = new byte[outlen];
        _engine.init(true, new KeyParameter(k));
        for (int i=0; i< n; i++) 
        {
            XOR(inputBlock, chainingValue, data, i*outlen);
            _engine.processBlock(inputBlock, 0, chainingValue, 0);
        }
        System.arraycopy(chainingValue, 0, bccOut, 0, bccOut.length);
    }

    private void copyIntToByteArray(byte[] buf, int value, int offSet)
    {
        buf[offSet + 0] = ((byte)(value >> 24));
        buf[offSet + 1] = ((byte)(value >> 16));
        buf[offSet + 2] = ((byte)(value >> 8));
        buf[offSet + 3] = ((byte)(value));
    }

    private byte[] getByteGen(byte[] input, int length)
    {
        // TODO:
        // return byteGenProcess(_underlyingCipher, input, length);
        return byteGenProcess(_engine, input, length);
    }

    // TODO: unholy mess of wrongness to get it to compile
    // this is so wrong, it's the capital of wrongville
    private byte[] byteGenProcess(BlockCipher engine, byte[] input, int lengthInBits)
    {
        int m = (lengthInBits / 8) / engine.getBlockSize();

        byte[] data = new byte[input.length];
        System.arraycopy(input, 0, data, 0, input.length);

        byte[] W = new byte[lengthInBits / 8];

        byte[] dig = new byte[engine.getBlockSize()];

        for (int i = 0; i <= m; i++)
        {
            engine.processBlock(data, data.length, dig, 0);

            int bytesToCopy = ((W.length - i * dig.length) > dig.length)
                    ? dig.length
                    : (W.length - i * dig.length);
            System.arraycopy(dig, 0, W, i * dig.length, bytesToCopy);

            addOneTo(data);
        }

        return W;
    }
}
