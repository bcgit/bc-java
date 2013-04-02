package org.bouncycastle.crypto.prng;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.encoders.Hex;

public class HashSP800DRBG implements DRBG
{
    private Digest                 _digest;
    private byte[]                 _V;
    private byte[]                 _C;
    private int                    _reseedCounter;
    private EntropySource          _entropySource;
    private int                    _securityStrength;
    
    private int                    _seedLength;

    public HashSP800DRBG(Digest digest, int seedlen, EntropySource entropySource, byte[] nonce,
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
        _seedLength = seedlen;
        // 1. seed_material = entropy_input || nonce || personalization_string.
        // 2. seed = Hash_df (seed_material, seedlen).
        // 3. V = seed.
        // 4. C = Hash_df ((0x00 || V), seedlen). Comment: Preceed V with a byte
        // of zeros.
        // 5. reseed_counter = 1.
        // 6. Return V, C, and reseed_counter as the initial_working_state

        int entropyLengthInBytes = securityStrength;
        byte[] entropy = entropySource.getEntropy(entropyLengthInBytes/8);
        
        System.out.println("Constructor Entropy: "+ new String(Hex.encode(entropy)));
        
        byte[] seedMaterial = new byte[entropy.length + nonce.length + personalisationString.length];
        
        System.arraycopy(entropy, 0, seedMaterial, 0, entropy.length);
        System.arraycopy(nonce, 0, seedMaterial, entropy.length, nonce.length);
        System.arraycopy(personalisationString, 0, seedMaterial, entropy.length + nonce.length,
                personalisationString.length);

        System.out.println("Constructor SeedMaterial: "+ new String(Hex.encode(seedMaterial)));

        byte[] seed = getDFBytes(seedMaterial, _seedLength);
        
        System.out.println("Constructor Seed: "+ new String(Hex.encode(seed)));

        _V = seed;
        byte[] subV = new byte[_V.length + 1];
        System.arraycopy(_V, 0, subV, 1, _V.length);
        _C = getDFBytes(subV, _seedLength);
        _reseedCounter = 1;
        
        System.out.println("Constructor V: "+ new String(Hex.encode(_V)));        
        System.out.println("Constructor C: "+ new String(Hex.encode(_C)));

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
        
        if (predictionResistant) 
        {
            reseed(additionalInput);
        }

        // 2.
        if (additionalInput != null)
        {
            byte[] newInput = new byte[1 + _V.length + additionalInput.length];
            newInput[0] = 0x02;
            System.arraycopy(_V, 0, newInput, 1, _V.length);
            // TODO: inOff / inLength
            System.arraycopy(additionalInput, 0, newInput, 1 + _V.length, additionalInput.length);
            byte[] w = getBytes(newInput);

            addTo(_V, w);
        }
        
        // 3.
        byte[] rv = getByteGen(_V, numberOfBits);
        
        // 4.
        byte[] subH = new byte[_V.length + 1];
        System.arraycopy(_V, 0, subH, 1, _V.length);
        subH[0] = 0x03;
        
        byte[] H = getBytes(subH);
        
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
        System.out.println("Generate V: "+ new String(Hex.encode(_V)));
        System.out.println("Generate C: "+ new String(Hex.encode(_C)));

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
    // Comment: Preceed with a byte of all
    // zeros.
    public void reseed(byte[] additionalInput)
    {
        if (additionalInput == null) 
        {
            additionalInput = new byte[0];
        }
        int entropyLengthInBytes = _securityStrength;
        byte[] entropy = _entropySource.getEntropy(entropyLengthInBytes/8);
        
        System.out.println("Reseed Entropy: "+ new String(Hex.encode(entropy)));
        
        byte[] seedMaterial = new byte[1+ _V.length + entropy.length + additionalInput.length];
        
        seedMaterial[0] = 0x01;
        System.arraycopy(_V, 0, seedMaterial, 1, _V.length);
        System.arraycopy(entropy, 0, seedMaterial, 1+_V.length, entropy.length);
        System.arraycopy(additionalInput, 0, seedMaterial, 1+_V.length+entropy.length,additionalInput.length);

        System.out.println("Reseed SeedMaterial: "+ new String(Hex.encode(seedMaterial)));

        byte[] seed = getDFBytes(seedMaterial, _seedLength);
        
        System.out.println("Reseed Seed: "+ new String(Hex.encode(seed)));

        _V = seed;
        byte[] subV = new byte[_V.length + 1];
        subV[0] = 0x00;
        System.arraycopy(_V, 0, subV, 1, _V.length);
        _C = getDFBytes(subV, _seedLength);
        _reseedCounter = 1;
        
        System.out.println("Reseed V: "+ new String(Hex.encode(_V)));
        System.out.println("Reseed C: "+ new String(Hex.encode(_C)));
    }
    
    
    // ---- Internal manipulation --- 
    // ---- Migrating from the external HashDF class --
    
    private byte[] getDFBytes(byte[] seedMaterial, int seedLength)
    {
        return hashDFProcess(_digest, seedLength, seedMaterial);
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
    
    private byte[] getBytes(byte[] input)
    {
        _digest.update(input, 0, input.length);
        byte[] hash = new byte[_digest.getDigestSize()];
        _digest.doFinal(hash, 0);
        return hash;
    }
    
    private byte[] getByteGen(byte[] input, int length)
    {
        return byteGenProcess(_digest, input, length);
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
