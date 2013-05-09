package org.bouncycastle.crypto.prng;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class CTRSP800DRBG
    implements SP80090DRBG
{
    private EntropySource         _entropySource;
    private BlockCipher           _engine;
    private int                   _keySizeInBits;
    private int                   _seedLength;
    
    // internal state
    private byte[]                _Key;
    private byte[]                _V;
    private int                   _reseedCounter = 0;

    public CTRSP800DRBG(BlockCipher engine, int keySizeInBits, EntropySource entropySource, byte[] nonce,
                        byte[] personalisationString, int securityStrength)
    {

        _entropySource = entropySource;
        _engine = engine;     
        
        _keySizeInBits = keySizeInBits;
        _seedLength = keySizeInBits + engine.getBlockSize() * 8;

        int entropyLengthInBytes = securityStrength;
        
        if (securityStrength > 256)
        {
            throw new IllegalStateException(
                            "Security strength is not supported by the derivation function");            
        }
            
        byte[] entropy = entropySource.getEntropy();  // Get_entropy_input

        System.out.println("Constructor Entropy: " + new String(Hex.encode(entropy)));

        CTR_DRBG_Instantiate_algorithm(entropy, nonce, personalisationString);
        
        System.err.println("Constructor V  : " + new String(Hex.encode(_V)));
        System.err.println("Constructor Key: " + new String(Hex.encode(_Key)));

    }

    private void CTR_DRBG_Instantiate_algorithm(byte[] entropy, byte[] nonce,
            byte[] personalisationString)
    {
        if (personalisationString == null)
        {
            personalisationString = new byte[0];
        }

        byte[] seedMaterial = Arrays.concatenate(entropy, nonce, personalisationString);

        System.out.println("Constructor SeedMaterial: " + new String(Hex.encode(seedMaterial)));

        byte[] seed = Block_Cipher_df(seedMaterial, _seedLength);

        System.out.println("Constructor Seed: " + new String(Hex.encode(seed)));

        int outlen = _engine.getBlockSize();

        _Key = new byte[(_keySizeInBits + 7) / 8];
        _V = new byte[outlen];

        CTR_DRBG_Update(seed, _Key, _V); 
        // _Key & _V are modified by this call
        System.out.println("Key: " + new String(Hex.encode(_Key)));
        System.out.println("V  : " + new String(Hex.encode(_V)));
        _reseedCounter = 1;
    }

    private void CTR_DRBG_Update(byte[] seed, byte[] key, byte[] v)
    {
        byte[] temp = new byte[seed.length];
        byte[] outputBlock = new byte[_engine.getBlockSize()];
        
        int i=0;
        int outLen = _engine.getBlockSize();

        _engine.init(true, new KeyParameter(key));
        while (i*outLen < seed.length)
        {
            addOneTo(v);
            _engine.processBlock(v, 0, outputBlock, 0);

            int bytesToCopy = ((temp.length - i * outLen) > outLen)
                    ? outLen : (temp.length - i * outLen);
            
            System.arraycopy(outputBlock, 0, temp, i * outLen, bytesToCopy);
            ++i;
        }
        System.err.println("seed: " + new String(Hex.encode(seed)));
        System.err.println("temp: " + new String(Hex.encode(temp)));
        XOR(temp, seed, temp, 0);
        System.err.println("temp: " + new String(Hex.encode(temp)));
        System.arraycopy(temp, 0, key, 0, key.length);
        System.arraycopy(temp, key.length, v, 0, v.length);
    }
    
    private void CTR_DRBG_Reseed_algorithm(EntropySource entropy, byte[] additionalInput) 
    {
        
        
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
    
    private static final byte[] K_BITS = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    
    private byte[] getBytes(byte[] input)
    {
        byte[] K = new byte[_keySizeInBits / 8];
        System.arraycopy(K_BITS, 0, K, 0, K.length); 
        _engine.init(true, new KeyParameter(K));
        byte[] out = new byte[_engine.getBlockSize()];
        _engine.processBlock(input, 0, out, 0);
        return out;
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
    private byte[] Block_Cipher_df(byte[] inputString, int bitLength)
    {
        int outLen = _engine.getBlockSize();
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
        System.err.println("S  :" + new String(Hex.encode(S)));
        byte[] temp = new byte[_keySizeInBits / 8 + outLen];
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

        byte[] X = new byte[outLen];
        System.arraycopy(temp, 0, K, 0, K.length);
        System.arraycopy(temp, K.length, X, 0, X.length);

        temp = new byte[bitLength / 2];

        i = 0;
        _engine.init(true, new KeyParameter(K));

        while (i * outLen < temp.length)
        {
            _engine.processBlock(X, 0, X, 0);

            int bytesToCopy = ((temp.length - i * outLen) > outLen)
                    ? outLen
                    : (temp.length - i * outLen);

            System.arraycopy(X, 0, temp, i * outLen, bytesToCopy);
            i++;
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

        _engine.processBlock(iV, 0, chainingValue, 0);

        for (int i = 0; i < n; i++)
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

    public int generate(byte[] output, byte[] additionalInput, boolean predictionResistant)
    {
        if (predictionResistant)
        {
            CTR_DRBG_Reseed_algorithm(_entropySource, additionalInput);
        }

        if (additionalInput != null)
        {
            additionalInput = Block_Cipher_df(additionalInput, _seedLength);
            CTR_DRBG_Update(additionalInput, _Key, _V);
        }
        else
        {
            additionalInput = new byte[_seedLength];
        }

        byte[] out = new byte[_V.length];

        _engine.init(true, new KeyParameter(_Key));

        for (int i = 0; i < output.length / out.length; i++)
        {
            addOneTo(_V);

            _engine.processBlock(_V, 0, out, 0);

            int bytesToCopy = ((output.length - i * out.length) > out.length)
                    ? out.length
                    : (output.length - i * _V.length);

            System.arraycopy(out, 0, output, i * out.length, bytesToCopy);
        }


        CTR_DRBG_Update(additionalInput, _Key, _V);

        _reseedCounter++;

        return output.length * 8;
    }

    public void reseed(byte[] additionalInput)
    {
        CTR_DRBG_Reseed_algorithm(_entropySource, additionalInput);
    }
}
