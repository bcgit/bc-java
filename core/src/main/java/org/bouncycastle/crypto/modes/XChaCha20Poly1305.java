package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.XChaCha20Engine;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Pack;

public class XChaCha20Poly1305 extends ChaCha20Poly1305 implements AEADCipher
{
    private static final int MAC_BYTES = 16;
    private static final int KEY_SIZE = 32;
    private static final int NONCE_SIZE = 24;

    @Override
    public String getAlgorithmName()
    {
        return "XChaCha20Poly1305";
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException
    {
        KeyParameter keyParam;
        byte[] nonce;
        byte[] aad = null;

        if (params instanceof AEADParameters)
        {
            AEADParameters aeadParams = (AEADParameters) params;
            int macSize = aeadParams.getMacSize();

            if (MAC_BYTES * 8 != macSize)
            {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSize);
            }

            keyParam = aeadParams.getKey();
            nonce = aeadParams.getNonce();
            aad = aeadParams.getAssociatedText();
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParams = (ParametersWithIV) params;
            keyParam = (KeyParameter) ivParams.getParameters();
            nonce = ivParams.getIV();
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to XChaCha20Poly1305");
        }

        // Validate nonce
        if (nonce == null || NONCE_SIZE != nonce.length)
        {
            throw new IllegalArgumentException("XChaCha20Poly1305 requires a 192 bit nonce");
        }

        // Validate key
        if (null == keyParam)
        {
            if (State.UNINITIALIZED == state)
            {
                throw new IllegalArgumentException("Key must be specified in initial init");
            }

            // Derive sub key from old key and new nonce using the HChaCha20 algorithm
            XChaCha20Engine xChaCha = new XChaCha20Engine();
            byte[] subKey = Pack.intToLittleEndian(xChaCha.hChaChaDeriveSubKey(key, nonce));

            keyParam = new KeyParameter(subKey);
        }
        else
        {
            if (KEY_SIZE != keyParam.getKey().length)
            {
                throw new IllegalArgumentException("Key must be 256 bits");
            }

            // Derive sub key using the HChaCha20 algorithm
            XChaCha20Engine xChaCha = new XChaCha20Engine();
            byte[] subKey = Pack.intToLittleEndian(xChaCha.hChaChaDeriveSubKey(keyParam.getKey(),
                nonce));

            keyParam = new KeyParameter(subKey);
        }

        // Use last 64 bits of nonce prefixed with 4 NUL bytes as nonce for ChaCha20Poly1305
        // Nonce reuse will be caught in super.init(...)
        byte[] chaChaNonce = new byte[12];
        System.arraycopy(nonce, 16, chaChaNonce, 4, 8);

        if (aad == null) {
            super.init(forEncryption, new ParametersWithIV(keyParam, chaChaNonce));
        } else {
            super.init(forEncryption, new AEADParameters(keyParam,
                8 * MAC_BYTES, chaChaNonce, aad));
        }
    }
}
