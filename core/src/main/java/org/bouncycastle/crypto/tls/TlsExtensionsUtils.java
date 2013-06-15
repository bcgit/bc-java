package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.util.Integers;

public class TlsExtensionsUtils
{
    public static final Integer EXT_status_request = Integers.valueOf(ExtensionType.status_request);

    public static void addOCSPStatusRequestExtension(Hashtable extensions, OCSPStatusRequest ocspStatusRequest)
        throws IOException
    {
        extensions.put(EXT_status_request, createOCSPStatusRequestExtension(ocspStatusRequest));
    }

    public static byte[] createOCSPStatusRequestExtension(OCSPStatusRequest ocspStatusRequest)
        throws IOException
    {
        if (ocspStatusRequest == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        ocspStatusRequest.encode(buf);
        return buf.toByteArray();
    }
}
