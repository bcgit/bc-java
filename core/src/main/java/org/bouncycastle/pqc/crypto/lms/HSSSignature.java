package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.io.Streams;

public class HSSSignature
    implements Encodable
{
    private final int lMinus1;
    private final LMSSignedPubKey[] signedPubKey;
    private final LMSSignature signature;

    public HSSSignature(int lMinus1, LMSSignedPubKey[] signedPubKey, LMSSignature signature)
    {
        this.lMinus1 = lMinus1;
        this.signedPubKey = signedPubKey;
        this.signature = signature;
    }


    /**
     * @param src byte[], InputStream or HSSSignature
     * @param L   The HSS depth, available from public key.
     * @return An HSSSignature instance.
     * @throws IOException
     */
    public static HSSSignature getInstance(Object src, int L)
        throws IOException
    {
        if (src instanceof HSSSignature)
        {
            return (HSSSignature)src;
        }
        else if (src instanceof DataInputStream)
        {

            int lminus = ((DataInputStream)src).readInt();
            if (lminus != L - 1)
            {
                throw new IllegalStateException("nspk exceeded maxNspk");
            }
            LMSSignedPubKey[] signedPubKeys = new LMSSignedPubKey[lminus];
            if (lminus != 0)
            {
                for (int t = 0; t < signedPubKeys.length; t++)
                {
                    signedPubKeys[t] = new LMSSignedPubKey(LMSSignature.getInstance(src), LMSPublicKeyParameters.getInstance(src));
                }
            }
            LMSSignature sig = LMSSignature.getInstance(src);

            return new HSSSignature(lminus, signedPubKeys, sig);
        }
        else if (src instanceof byte[])
        {
            InputStream in = null;
            try // 1.5 / 1.6 compatibility
            {
                in = new DataInputStream(new ByteArrayInputStream((byte[])src));
                return getInstance(in, L);
            }
            finally
            {
               if (in != null) in.close();
            }
        }
        else if (src instanceof InputStream)
        {
            return getInstance(Streams.readAll((InputStream)src),L);
        }

        throw new IllegalArgumentException("cannot parse " + src);
    }


    public int getlMinus1()
    {
        return lMinus1;
    }

    public LMSSignedPubKey[] getSignedPubKey()
    {
        return signedPubKey;
    }

    public LMSSignature getSignature()
    {
        return signature;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }

        HSSSignature signature1 = (HSSSignature)o;

        if (lMinus1 != signature1.lMinus1)
        {
            return false;
        }
        // Probably incorrect - comparing Object[] arrays with Arrays.equals

        if (signedPubKey.length != signature1.signedPubKey.length)
        {
            return false;
        }

        for (int t = 0; t < signedPubKey.length; t++)
        {
            if (!signedPubKey[t].equals(signature1.signedPubKey[t]))
            {
                return false;
            }
        }

        return signature != null ? signature.equals(signature1.signature) : signature1.signature == null;
    }

    @Override
    public int hashCode()
    {
        int result = lMinus1;
        result = 31 * result + Arrays.hashCode(signedPubKey);
        result = 31 * result + (signature != null ? signature.hashCode() : 0);
        return result;
    }

    public byte[] getEncoded()
        throws IOException
    {
        Composer composer = Composer.compose();
        composer.u32str(lMinus1);
        if (signedPubKey != null)
        {
            for (LMSSignedPubKey sigPub : signedPubKey)
            {
                composer.bytes(sigPub);
            }
        }
        composer.bytes(signature);
        return composer.build();

    }

}
