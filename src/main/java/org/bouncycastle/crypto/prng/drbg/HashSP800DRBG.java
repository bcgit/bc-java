package org.bouncycastle.crypto.prng.drbg;

import java.util.Hashtable;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

public class HashSP800DRBG implements SP80090DRBG
{
    private final static byte[]     ONE = { 0x01 };
    private final static int        RESEED_MAX = 100000;
    private final static Hashtable  seedlens = new Hashtable();

    static
    {
        seedlens.put("SHA-1", Integers.valueOf(440));
        seedlens.put("SHA-224", Integers.valueOf(440));
        seedlens.put("SHA-256", Integers.valueOf(440));
        seedlens.put("SHA-512/256", Integers.valueOf(440));
        seedlens.put("SHA-512/224", Integers.valueOf(440));
        seedlens.put("SHA-384", Integers.valueOf(888));
        seedlens.put("SHA-512", Integers.valueOf(888));
    }

    private Digest                 _digest;
    private byte[]                 _V;
    private byte[]                 _C;
    private int                    _reseedCounter;
    private EntropySource _entropySource;
    private int                    _securityStrength;
    private int _seedLength;

    public HashSP800DRBG(Digest digest, EntropySource entropySource, byte[] nonce,
                         byte[] personalisationString, int securityStrength)
    {
        if (securityStrength > digest.getDigestSize() * 8) // TODO: this may, or may not be correct, but it's good enough for now
        {
            throw new IllegalStateException(
                    "Security strength is not supported by the derivation function");
        }
        
        _digest = digest;
        _entropySource = entropySource;
        _securityStrength = securityStrength;
        _seedLength = ((Integer)seedlens.get(digest.getAlgorithmName())).intValue();

        // 1. seed_material = entropy_input || nonce || personalization_string.
        // 2. seed = Hash_df (seed_material, seedlen).
        // 3. V = seed.
        // 4. C = Hash_df ((0x00 || V), seedlen). Comment: Preceed V with a byte
        // of zeros.
        // 5. reseed_counter = 1.
        // 6. Return V, C, and reseed_counter as the initial_working_state

        byte[] entropy = entropySource.getEntropy();
        byte[] seedMaterial = Arrays.concatenate(entropy, nonce, personalisationString);
        byte[] seed = hash_df(seedMaterial, _seedLength);

        _V = seed;
        byte[] subV = new byte[_V.length + 1];
        System.arraycopy(_V, 0, subV, 1, _V.length);
        _C = hash_df(subV, _seedLength);
        _reseedCounter = 1;
        
//        System.out.println("Constructor V: "+ new String(Hex.encode(_V)));
//        System.out.println("Constructor C: "+ new String(Hex.encode(_C)));

    }

    // 1. If reseed_counter > reseed_interval, then return an indication that a
    // reseed is required.
    // 2. If (additional_input != Null), then do
    // 2.1 w = Hash (0x02 || V || additional_input).
    // 2.2 V = (V + w) mod 2^seedlen
    // .
    // 3. (returned_bits) = Hashgen (requested_number_of_bits, V).
    // 4. H = Hash (0x03 || V).
    // 5. V = (V + H + C + reseed_counter) mod 2^seedlen
    // .
    // 6. reseed_counter = reseed_counter + 1.
    // 7. Return SUCCESS, returned_bits, and the new values of V, C, and
    // reseed_counter for the new_working_state.
    public int generate(byte[] output, byte[] additionalInput, boolean predictionResistant)
    {
        int numberOfBits = output.length*8;
        
        if (predictionResistant || _reseedCounter > RESEED_MAX) 
        {   
            reseed(additionalInput);
            additionalInput = null;
        }

        // 2.
        if (additionalInput != null)
        {
            byte[] newInput = new byte[1 + _V.length + additionalInput.length];
            newInput[0] = 0x02;
            System.arraycopy(_V, 0, newInput, 1, _V.length);
            // TODO: inOff / inLength
            System.arraycopy(additionalInput, 0, newInput, 1 + _V.length, additionalInput.length);
            byte[] w = hash(newInput);

            addTo(_V, w);
        }
        
        // 3.
        byte[] rv = hashgen(_V, numberOfBits);
        
        // 4.
        byte[] subH = new byte[_V.length + 1];
        System.arraycopy(_V, 0, subH, 1, _V.length);
        subH[0] = 0x03;
        
        byte[] H = hash(subH);
        
        // 5.
        addTo(_V, H);
        addTo(_V, _C);
        byte[] c = new byte[4];
        c[0] = (byte)(_reseedCounter >> 24);
        c[1] = (byte)(_reseedCounter >> 16);
        c[2] = (byte)(_reseedCounter >> 8);
        c[3] = (byte)_reseedCounter;
        
        addTo(_V, c);
        _reseedCounter++;

        System.arraycopy(rv, 0, output, 0, output.length);
//        System.out.println("Generate V: "+ new String(Hex.encode(_V)));
//        System.out.println("Generate C: "+ new String(Hex.encode(_C)));

        return numberOfBits;
    }

    // this will always add the shorter length byte array mathematically to the
    // longer length byte array.
    // be careful....
    private void addTo(byte[] longer, byte[] shorter)
    {
        int carry = 0;
        for (int i=1;i <= shorter.length; i++) // warning
        {
            int res = (longer[longer.length-i] & 0xff) + (shorter[shorter.length-i] & 0xff) + carry;
            carry = (res > 0xff) ? 1 : 0;
            longer[longer.length-i] = (byte)res;
        }
        
        for (int i=shorter.length+1;i <= longer.length; i++) // warning
        {
            int res = (longer[longer.length-i] & 0xff) + carry;
            carry = (res > 0xff) ? 1 : 0;
            longer[longer.length-i] = (byte)res;
        }
    }

    // 1. seed_material = 0x01 || V || entropy_input || additional_input.
    //
    // 2. seed = Hash_df (seed_material, seedlen).
    //
    // 3. V = seed.
    //
    // 4. C = Hash_df ((0x00 || V), seedlen).
    //
    // 5. reseed_counter = 1.
    //
    // 6. Return V, C, and reseed_counter for the new_working_state.
    //
    // Comment: Precede with a byte of all zeros.
    public void reseed(byte[] additionalInput)
    {
        if (additionalInput == null) 
        {
            additionalInput = new byte[0];
        }

        byte[] entropy = _entropySource.getEntropy();
        
//        System.out.println("Reseed Entropy: "+ new String(Hex.encode(entropy)));
        
        byte[] seedMaterial = Arrays.concatenate(ONE, _V, entropy, additionalInput);

//        System.out.println("Reseed SeedMaterial: "+ new String(Hex.encode(seedMaterial)));

        byte[] seed = hash_df(seedMaterial, _seedLength);
        
//        System.out.println("Reseed Seed: "+ new String(Hex.encode(seed)));

        _V = seed;
        byte[] subV = new byte[_V.length + 1];
        subV[0] = 0x00;
        System.arraycopy(_V, 0, subV, 1, _V.length);
        _C = hash_df(subV, _seedLength);
        _reseedCounter = 1;
        
//        System.out.println("Reseed V: "+ new String(Hex.encode(_V)));
//        System.out.println("Reseed C: "+ new String(Hex.encode(_C)));
    }
    
    
    // ---- Internal manipulation --- 
    // ---- Migrating from the external HashDF class --
    

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
    private byte[] hash_df(byte[] seedMaterial, int seedLength)
    {
        byte[] temp = new byte[seedLength / 8];

        int len = temp.length / _digest.getDigestSize();
        int counter = 1;

        byte[] dig = new byte[_digest.getDigestSize()];

        for (int i = 0; i <= len; i++)
        {
            _digest.update((byte)counter);

            _digest.update((byte)(seedLength >> 24));
            _digest.update((byte)(seedLength >> 16));
            _digest.update((byte)(seedLength >> 8));
            _digest.update((byte)seedLength);

            _digest.update(seedMaterial, 0, seedMaterial.length);

            _digest.doFinal(dig, 0);

            int bytesToCopy = ((temp.length - i * dig.length) > dig.length)
                    ? dig.length
                    : (temp.length - i * dig.length);
            System.arraycopy(dig, 0, temp, i * dig.length, bytesToCopy);

            counter++;
        }

        // do a left shift to get rid of excess bits.
        if (seedLength % 8 != 0)
        {
            int shift = 8 - (seedLength % 8);
            int carry = 0;

            for (int i = 0; i != temp.length; i++)
            {
                int b = temp[i] & 0xff;
                temp[i] = (byte)((b >>> shift) | (carry << (8 - shift)));
                carry = b;
            }
        }

        return temp;
    }
    
    private byte[] hash(byte[] input)
    {
        _digest.update(input, 0, input.length);
        byte[] hash = new byte[_digest.getDigestSize()];
        _digest.doFinal(hash, 0);
        return hash;
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
    private byte[] hashgen(byte[] input, int lengthInBits)
    {
        int digestSize = _digest.getDigestSize();
        int m = (lengthInBits / 8) / digestSize;

        byte[] data = new byte[input.length];
        System.arraycopy(input, 0, data, 0, input.length);

        byte[] W = new byte[lengthInBits / 8];

        byte[] dig;
        for (int i = 0; i <= m; i++)
        {
            dig = hash(data);

            int bytesToCopy = ((W.length - i * dig.length) > dig.length)
                    ? dig.length
                    : (W.length - i * dig.length);
            System.arraycopy(dig, 0, W, i * dig.length, bytesToCopy);

            addTo(data, ONE);
        }

        return W;
    }    
}
