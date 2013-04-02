package org.bouncycastle.crypto.prng;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class CTRSP800DRBG
{
    private EntropySource         _entropySource;
    private BlockCipher           _engine;
    
    // internal state
    private byte[]                _Key;
    private byte[]                _V;
    private int                   _reseedCounter;

    public CTRSP800DRBG(CTRDerivationFunction function, EntropySource entropySource, byte[] nonce,
            byte[] personalisationString, int securityStrength)
    {

        _entropySource = entropySource;
        _engine = function.getEngine();

        int entropyLengthInBytes = securityStrength;
        byte[] entropy = entropySource.getEntropy(entropyLengthInBytes / 8);

        System.out.println("Constructor Entropy: " + new String(Hex.encode(entropy)));

        byte[] seedMaterial = new byte[entropy.length + nonce.length + personalisationString.length];

        System.arraycopy(entropy, 0, seedMaterial, 0, entropy.length);
        System.arraycopy(nonce, 0, seedMaterial, entropy.length, nonce.length);
        System.arraycopy(personalisationString, 0, seedMaterial, entropy.length + nonce.length,
                personalisationString.length);

        System.out.println("Constructor SeedMaterial: " + new String(Hex.encode(seedMaterial)));

        byte[] seed = function.getDFBytes(seedMaterial, function.getSeedlength());

        System.out.println("Constructor Seed: " + new String(Hex.encode(seed)));

        int outlen = function.getEngineBlockSize();
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

}
