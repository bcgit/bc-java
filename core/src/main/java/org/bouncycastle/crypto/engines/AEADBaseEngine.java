package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

abstract class AEADBaseEngine
    implements AEADCipher
{
    protected boolean forEncryption;
    protected String algorithmName;
    protected int KEY_SIZE;
    protected int IV_SIZE;
    protected int MAC_SIZE;
    protected byte[] initialAssociatedText;
    protected byte[] mac;

    @Override
    public String getAlgorithmName()
    {
        return algorithmName;
    }

    public int getKeyBytesSize()
    {
        return KEY_SIZE;
    }

    public int getIVBytesSize()
    {
        return IV_SIZE;
    }

    public byte[] getMac()
    {
        return mac;
    }

    public void reset()
    {
        reset(true);
    }

    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        return processBytes(new byte[]{in}, 0, 1, out, outOff);
    }

    public void init(boolean forEncryption, CipherParameters params)
    {
        this.forEncryption = forEncryption;
        KeyParameter key;
        byte[] npub;
        byte[] k;

        if (params instanceof AEADParameters)
        {
            AEADParameters aeadParameters = (AEADParameters)params;
            key = aeadParameters.getKey();
            npub = aeadParameters.getNonce();
            initialAssociatedText = aeadParameters.getAssociatedText();

            int macSizeBits = aeadParameters.getMacSize();
            if (macSizeBits != MAC_SIZE * 8)
            {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV withIV = (ParametersWithIV)params;
            key = (KeyParameter)withIV.getParameters();
            npub = withIV.getIV();
            initialAssociatedText = null;
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to " + algorithmName);
        }

        if (key == null)
        {
            throw new IllegalArgumentException(algorithmName + " Init parameters must include a key");
        }
        if (npub == null || npub.length != IV_SIZE)
        {
            throw new IllegalArgumentException(algorithmName + " requires exactly " + IV_SIZE + " bytes of IV");
        }

        k = key.getKey();
        if (k.length != KEY_SIZE)
        {
            throw new IllegalArgumentException(algorithmName + " key must be " + KEY_SIZE + " bytes long");
        }

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(
            this.getAlgorithmName(), 128, params, Utils.getPurpose(forEncryption)));

        init(k, npub);
        if (initialAssociatedText != null)
        {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }

    protected abstract void init(byte[] key, byte[] iv);

    protected void reset(boolean clearMac)
    {
        if (clearMac)
        {
            mac = null;
        }
    }
}
