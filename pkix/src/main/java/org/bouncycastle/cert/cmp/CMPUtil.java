package org.bouncycastle.cert.cmp;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;

class CMPUtil
{
    static void derEncodeToStream(ASN1Object obj, OutputStream stream)
    {
        try
        {
            obj.encodeTo(stream, ASN1Encoding.DER);
            stream.close();
        }
        catch (IOException e)
        {
            throw new CMPRuntimeException("unable to DER encode object: " + e.getMessage(), e);
        }
    }
}
