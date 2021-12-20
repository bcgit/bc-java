package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageEncryptor;

import java.security.SecureRandom;

public class CMCECipher
    implements MessageEncryptor
{
    // the source of randomness
    private SecureRandom sr;

//    // the Classical CMCE main parameters
//    private int n, t, m;

    private CMCEEngine engine;

    private CMCEKeyParameters key;
    private byte[] sessionKey;
    private boolean forEncryption;

    public byte[] getSessionKey()
    {
        return sessionKey;
    }

    @Override
    public void init(boolean forEncrypting,
                     CipherParameters param)
    {
        this.forEncryption = forEncrypting;
        if (forEncrypting)
        {
            if (param instanceof ParametersWithRandom)
            {
                key = ((CMCEPublicKeyParameters)((ParametersWithRandom)param).getParameters());
            }
            else
            {
                key = ((CMCEPublicKeyParameters)param);
            }
        }
        else
        {
            key = ((CMCEPrivateKeyParameters)param);
        }
        initCipher(key.getParameters());
    }

    /**
     * Generate session key and cipher text with public key
     *
     * @param input nothing?
     * stores session key
     * @return the cipher text
     */
    @Override
    public byte[] messageEncrypt(byte[] input)
    {
        if (!forEncryption)
        {
            throw new IllegalStateException("cipher initialised for decryption");
        }
        byte[] cipher_text = new byte[engine.getCipherTextSize()];
        sessionKey = new byte[32];
        engine.kem_enc(cipher_text, sessionKey, ((CMCEPublicKeyParameters)key).getPublicKey(), key.getParameters().getRandom());
        return cipher_text;
    }


    private void initCipher(CMCEParameters param)
    {
        engine = param.getEngine();
    }

    /**
     * Decrypt a cipher text.
     *
     * @param input the cipher text
     * @return the session key
     * @throws InvalidCipherTextException if the cipher text is invalid.
     */
    public byte[] messageDecrypt(byte[] input)
            throws InvalidCipherTextException
    {
        if (forEncryption)
        {
            throw new IllegalStateException("cipher initialised for decryption");
        }
        byte[] session_key = new byte[32];
        engine.kem_dec(session_key, input, ((CMCEPrivateKeyParameters)key).getPrivateKey());
        return session_key;
    }

}
