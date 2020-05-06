package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.io.Streams;

public class HSSPublicKeyParameters
    extends LMSKeyParameters
    implements LMSContextBasedVerifier
{
    private final int l;
    private final LMSPublicKeyParameters lmsPublicKey;

    public HSSPublicKeyParameters(int l, LMSPublicKeyParameters lmsPublicKey)
    {
        super(false);

        this.l = l;
        this.lmsPublicKey = lmsPublicKey;
    }

    public static HSSPublicKeyParameters getInstance(Object src)
        throws IOException
    {
        if (src instanceof HSSPublicKeyParameters)
        {
            return (HSSPublicKeyParameters)src;
        }
        else if (src instanceof DataInputStream)
        {
            int L = ((DataInputStream)src).readInt();
            LMSPublicKeyParameters lmsPublicKey = LMSPublicKeyParameters.getInstance(src);
            return new HSSPublicKeyParameters(L, lmsPublicKey);
        }
        else if (src instanceof byte[])
        {
            InputStream in = null;
            try // 1.5 / 1.6 compatibility
            {
                in = new DataInputStream(new ByteArrayInputStream((byte[])src));
                return getInstance(in);
            }
            finally
            {
                if (in != null) in.close();
            }
        }
        else if (src instanceof InputStream)
        {
            return getInstance(Streams.readAll((InputStream)src));
        }

        throw new IllegalArgumentException("cannot parse " + src);
    }

    public int getL()
    {
        return l;
    }

    public LMSPublicKeyParameters getLMSPublicKey()
    {
        return lmsPublicKey;
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

        HSSPublicKeyParameters publicKey = (HSSPublicKeyParameters)o;

        if (l != publicKey.l)
        {
            return false;
        }
        return lmsPublicKey.equals(publicKey.lmsPublicKey);
    }

    @Override
    public int hashCode()
    {
        int result = l;
        result = 31 * result + lmsPublicKey.hashCode();
        return result;
    }

    public byte[] getEncoded()
        throws IOException
    {
        return Composer.compose().u32str(l)
            .bytes(lmsPublicKey.getEncoded())
            .build();
    }

    public LMSContext generateLMSContext(byte[] sigEnc)
    {
        HSSSignature signature;
        try
        {
            signature = HSSSignature.getInstance(sigEnc, getL());
        }
        catch (IOException e)
        {
            throw new IllegalStateException("cannot parse signature: " + e.getMessage());
        }

        LMSSignedPubKey[] signedPubKeys = signature.getSignedPubKey();
        LMSPublicKeyParameters key = signedPubKeys[signedPubKeys.length - 1].getPublicKey();

        return key.generateOtsContext(signature.getSignature()).withSignedPublicKeys(signedPubKeys);
    }

    public boolean verify(LMSContext context)
    {
        boolean failed = false;

        LMSSignedPubKey[] sigKeys = context.getSignedPubKeys();

        if (sigKeys.length != getL() - 1)
        {
            return false;
        }

        LMSPublicKeyParameters key = getLMSPublicKey();

        for (int i = 0; i < sigKeys.length; i++)
        {
            LMSSignature sig = sigKeys[i].getSignature();
            byte[] msg = sigKeys[i].getPublicKey().toByteArray();
            if (!LMS.verifySignature(key, sig, msg))
            {
                failed = true;
            }
            key = sigKeys[i].getPublicKey();
        }

        return !failed & key.verify(context);
    }
}
