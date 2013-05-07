package org.bouncycastle.crypto.prng;

import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

public class HMacSP800DRBG
    implements SP80090DRBG
{
    private byte[] _K;
    private byte[] _V;
    private int _reseedCounter;
    private EntropySource _entropySource;
    private HMac _hMac;

    public HMacSP800DRBG(HMac hMac, EntropySource entropySource, byte[] nonce,
                         byte[] personalisationString, int securityStrength)
    {
        // TODO: validate security strength

        _entropySource = entropySource;
        _hMac = hMac;

        // TODO: validate entropy length
        byte[] entropy = entropySource.getEntropy();

        byte[] seedMaterial = new byte[entropy.length + nonce.length + personalisationString.length];

        System.arraycopy(entropy, 0, seedMaterial, 0, entropy.length);
        System.arraycopy(nonce, 0, seedMaterial, entropy.length, nonce.length);
        System.arraycopy(personalisationString, 0, seedMaterial, entropy.length + nonce.length, personalisationString.length);

        _K = new byte[hMac.getUnderlyingDigest().getDigestSize()];
        _V = new byte[_K.length];
        Arrays.fill(_V, (byte)1);

        hmac_DRBG_Update(seedMaterial);

        _reseedCounter = 1;
    }

    private void hmac_DRBG_Update(byte[] seedMaterial)
    {
        hmac_DRBG_Update_Func(seedMaterial, (byte)0x00);
        if (seedMaterial != null)
        {
            hmac_DRBG_Update_Func(seedMaterial, (byte)0x01);
        }
    }

    private void hmac_DRBG_Update_Func(byte[] seedMaterial, byte vValue)
    {
        _hMac.init(new KeyParameter(_K));

        _hMac.update(_V, 0, _V.length);
        _hMac.update(vValue);

        if (seedMaterial != null)
        {
            _hMac.update(seedMaterial, 0, seedMaterial.length);
        }

        _hMac.doFinal(_K, 0);

        _hMac.init(new KeyParameter(_K));
        _hMac.update(_V, 0, _V.length);

        _hMac.doFinal(_V, 0);
    }

    public int generate(byte[] output, byte[] additionalInput, boolean predictionResistant)
    {
        // TODO: check reseed counter

        int numberOfBits = output.length * 8;

        if (predictionResistant)
        {
            reseed(additionalInput);
            additionalInput = null;
        }

        // 2.
        if (additionalInput != null)
        {
            hmac_DRBG_Update(additionalInput);
        }

        // 3.
        byte[] rv = new byte[output.length];

        int m = output.length / _V.length;

        _hMac.init(new KeyParameter(_K));

        for (int i = 0; i < m; i++)
        {
            _hMac.update(_V, 0, _V.length);
            _hMac.doFinal(_V, 0);

            System.arraycopy(_V, 0, rv, i * _V.length, _V.length);
        }

        if (m * _V.length < rv.length)
        {
            _hMac.update(_V, 0, _V.length);
            _hMac.doFinal(_V, 0);

            System.arraycopy(_V, 0, rv, m * _V.length, rv.length - (m * _V.length));
        }

        hmac_DRBG_Update(additionalInput);

        _reseedCounter++;

        System.arraycopy(rv, 0, output, 0, output.length);

        return numberOfBits;
    }

    public void reseed(byte[] additionalInput)
    {
        if (additionalInput == null)
        {
            additionalInput = new byte[0];
        }

        byte[] entropy = _entropySource.getEntropy();

        byte[] seedMaterial = new byte[entropy.length +  additionalInput.length];

        System.arraycopy(entropy, 0, seedMaterial, 0, entropy.length);
        System.arraycopy(additionalInput, 0, seedMaterial, entropy.length, additionalInput.length);

        hmac_DRBG_Update(seedMaterial);

        _reseedCounter = 1;
    }
}
