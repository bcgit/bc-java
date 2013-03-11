package org.bouncycastle.crypto.prng;

public class SP800DRBG implements DRBG
{
    private DRBGDerivationFunction _function;
    private byte[]                 _V;
    private byte[]                 _C;
    private int                    _reseedCounter;

    public SP800DRBG(DRBGDerivationFunction function, EntropySource entropySource, byte[] nonce,
            byte[] personalisationString, int securityStrength)
    {
        if (securityStrength > function.getSecurityStrength())
        {
            throw new IllegalStateException(
                    "Security strength is not supported by the derivation function");
        }
        _function = function;
        // 1. seed_material = entropy_input || nonce || personalization_string.
        // 2. seed = Hash_df (seed_material, seedlen).
        // 3. V = seed.
        // 4. C = Hash_df ((0x00 || V), seedlen). Comment: Preceed V with a byte
        // of zeros.
        // 5. reseed_counter = 1.
        // 6. Return V, C, and reseed_counter as the initial_working_state

        int entropyLengthInBytes = securityStrength;
        byte[] entropy = entropySource.getEntropy(entropyLengthInBytes);
        byte[] seedMaterial = new byte[entropy.length + nonce.length + personalisationString.length];
        System.arraycopy(entropy, 0, seedMaterial, 0, entropy.length);
        System.arraycopy(nonce, 0, seedMaterial, entropy.length, nonce.length);
        System.arraycopy(personalisationString, 0, seedMaterial, entropy.length + nonce.length,
                personalisationString.length);

        byte[] seed = function.getDFBytes(seedMaterial, function.getSeedlength());

        _V = seed;
        byte[] subV = new byte[_V.length + 1];
        System.arraycopy(_V, 0, subV, 1, _V.length);
        _C = function.getDFBytes(subV, function.getSeedlength());
        _reseedCounter = 1;

    }

    // 1. If reseed_counter > reseed_interval, then return an indication that a
    // reseed is
    // required.
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
    public int generate(byte[] output, byte[] additionalInput, int inOff, int inLen)
    {
        int numberOfBits = output.length*8;
        
        if (_reseedCounter > 10) // so lame:: TODO
        {
            return 0;
        }

        // 2.
        if (additionalInput != null)
        {
            byte[] newInput = new byte[1 + _V.length + additionalInput.length];
            newInput[0] = 0x02;
            System.arraycopy(_V, 0, newInput, 1, _V.length);
            // TODO: inOff / inLength
            System.arraycopy(additionalInput, 0, newInput, 1 + _V.length, additionalInput.length);
            byte[] w = _function.getBytes(newInput);

            addTo(_V, w);
        }
        
        // 3.
        byte[] rv = _function.getByteGen(_V, numberOfBits);
        
        // 4.
        byte[] subH = new byte[_V.length + 1];
        System.arraycopy(_V, 0, subH, 1, _V.length);
        subH[0] = 0x03;
        
        byte[] H = _function.getBytes(subH);
        
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
    
    public void reseed(byte[] additionalInput)
    {
    }

}
