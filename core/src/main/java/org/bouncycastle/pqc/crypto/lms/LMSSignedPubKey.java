package org.bouncycastle.pqc.crypto.lms;

import java.io.IOException;

import org.bouncycastle.util.Encodable;

class LMSSignedPubKey
    implements Encodable
{
    private final LMSSignature signature;
    private final LMSPublicKeyParameters publicKey;

    public LMSSignedPubKey(LMSSignature signature, LMSPublicKeyParameters publicKey)
    {
        this.signature = signature;
        this.publicKey = publicKey;
    }


    public LMSSignature getSignature()
    {
        return signature;
    }

    public LMSPublicKeyParameters getPublicKey()
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

    public byte[] getEncoded()
        throws IOException
    {
        return Composer.compose()
            .bytes(signature.getEncoded())
            .bytes(publicKey.getEncoded())
            .build();
    }
}
