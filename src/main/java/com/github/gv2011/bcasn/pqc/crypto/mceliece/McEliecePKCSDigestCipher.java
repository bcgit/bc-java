package com.github.gv2011.bcasn.pqc.crypto.mceliece;


import com.github.gv2011.bcasn.crypto.CipherParameters;
import com.github.gv2011.bcasn.crypto.Digest;
import com.github.gv2011.bcasn.crypto.params.AsymmetricKeyParameter;
import com.github.gv2011.bcasn.crypto.params.ParametersWithRandom;
import com.github.gv2011.bcasn.pqc.crypto.MessageEncryptor;

// TODO should implement some interface?
public class McEliecePKCSDigestCipher
{

    private final Digest messDigest;

    private final MessageEncryptor mcElieceCipher;

    private boolean forEncrypting;


    public McEliecePKCSDigestCipher(MessageEncryptor mcElieceCipher, Digest messDigest)
    {
        this.mcElieceCipher = mcElieceCipher;
        this.messDigest = messDigest;
    }


    public void init(boolean forEncrypting,
                     CipherParameters param)
    {

        this.forEncrypting = forEncrypting;
        AsymmetricKeyParameter k;

        if (param instanceof ParametersWithRandom)
        {
            k = (AsymmetricKeyParameter)((ParametersWithRandom)param).getParameters();
        }
        else
        {
            k = (AsymmetricKeyParameter)param;
        }

        if (forEncrypting && k.isPrivate())
        {
            throw new IllegalArgumentException("Encrypting Requires Public Key.");
        }

        if (!forEncrypting && !k.isPrivate())
        {
            throw new IllegalArgumentException("Decrypting Requires Private Key.");
        }

        reset();

        mcElieceCipher.init(forEncrypting, param);
    }


    public byte[] messageEncrypt()
    {
        if (!forEncrypting)
        {
            throw new IllegalStateException("McEliecePKCSDigestCipher not initialised for encrypting.");
        }

        byte[] hash = new byte[messDigest.getDigestSize()];
        messDigest.doFinal(hash, 0);
        byte[] enc = null;

        try
        {
            enc = mcElieceCipher.messageEncrypt(hash);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }


        return enc;
    }


    public byte[] messageDecrypt(byte[] ciphertext)
    {
        byte[] output = null;
        if (forEncrypting)
        {
            throw new IllegalStateException("McEliecePKCSDigestCipher not initialised for decrypting.");
        }


        try
        {
            output = mcElieceCipher.messageDecrypt(ciphertext);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }


        return output;
    }


    public void update(byte b)
    {
        messDigest.update(b);

    }

    public void update(byte[] in, int off, int len)
    {
        messDigest.update(in, off, len);

    }


    public void reset()
    {
        messDigest.reset();

    }


}
