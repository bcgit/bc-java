package org.bouncycastle.pqc.crypto.lms;

import java.io.IOException;

import org.bouncycastle.util.Encodable;

public class LMSSignedPubKey
    implements Encodable
{
    private final LMSSignature signature;
    private final LmsPublicKey publicKey;

    public LMSSignedPubKey(LMSSignature signature, LmsPublicKey publicKey)
    {
        this.signature = signature;
        this.publicKey = publicKey;
    }

    static LMSSignedPubKey[] sliceTo(LMSSignedPubKey[] source, int len)
    {
        LMSSignedPubKey[] subList = new LMSSignedPubKey[len];
        System.arraycopy(source, 0, subList, 0, len);
        return subList;
    }

    public LMSSignature getSignature()
    {
        return signature;
    }

    public LmsPublicKey getPublicKey()
    {
        return publicKey;
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

        LMSSignedPubKey that = (LMSSignedPubKey)o;

        if (signature != null ? !signature.equals(that.signature) : that.signature != null)
        {
            return false;
        }
        return publicKey != null ? publicKey.equals(that.publicKey) : that.publicKey == null;
    }

    @Override
    public int hashCode()
    {
        int result = signature != null ? signature.hashCode() : 0;
        result = 31 * result + (publicKey != null ? publicKey.hashCode() : 0);
        return result;
    }

    @Override
    public byte[] getEncoded()
        throws IOException
    {
        return Composer.compose()
            .bytes(signature.getEncoded())
            .bytes(publicKey.getEncoded())
            .build();

    }
}
