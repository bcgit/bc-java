package org.bouncycastle.crypto.params;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.crypto.signers.LMSContextBasedVerifier;
import org.bouncycastle.crypto.signers.lms.LMSContext;
import org.bouncycastle.crypto.signers.lms.LMSEngine;
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

        if (lmsPublicKey == null)
        {
            throw new NullPointerException("lmsPublicKey");
        }

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
            if (L < 1 || L > 8)    // RFC 8554, Section 6.
            {
                throw new IOException("L value of HSS public key out of range: " + L);
            }
            LMSPublicKeyParameters lmsPublicKey = LMSPublicKeyParameters.getInstance(src);
            return new HSSPublicKeyParameters(L, lmsPublicKey);
        }
        else if (src instanceof byte[])
        {
            InputStream in = null;
            try // 1.5 / 1.6 compatibility
            {
                in = new DataInputStream(new ByteArrayInputStream((byte[])src));
                HSSPublicKeyParameters pKey = getInstance(in);
                // RFC 8554, Section 5.3 / 6.1: nothing may follow the public key.
                if (in.available() != 0)
                {
                    throw new IOException("unexpected data found after HSS public key");
                }
                return pKey;
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
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        u32str(l, bOut);
        bytes(lmsPublicKey.getEncoded(), bOut);

        return bOut.toByteArray();
    }

    public LMSContext generateLMSContext(byte[] sigEnc)
    {
        return LMSEngine.generateHSSVerifyContext(this, sigEnc);
    }

    public boolean verify(LMSContext context)
    {
        return LMSEngine.verifyHSSSignature(this, context);
    }
}
