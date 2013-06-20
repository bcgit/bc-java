package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.util.Integers;

public class TlsExtensionsUtils
{
    public static final Integer EXT_server_name = Integers.valueOf(ExtensionType.server_name);
    public static final Integer EXT_status_request = Integers.valueOf(ExtensionType.status_request);

    public static void addServerNameExtension(Hashtable extensions, ServerNameList serverNameList)
        throws IOException
    {
        extensions.put(EXT_server_name, createServerNameExtension(serverNameList));
    }

    public static void addStatusRequestExtension(Hashtable extensions, CertificateStatusRequest statusRequest)
        throws IOException
    {
        extensions.put(EXT_status_request, createStatusRequestExtension(statusRequest));
    }

    public static ServerNameList getServerNameExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_server_name);
        return extensionData == null ? null : readServerNameExtension(extensionData);
    }

    public static CertificateStatusRequest getStatusRequestExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_status_request);
        return extensionData == null ? null : readStatusRequestExtension(extensionData);
    }

    public static byte[] createServerNameExtension(ServerNameList serverNameList)
        throws IOException
    {
        if (serverNameList == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        
        serverNameList.encode(buf);

        return buf.toByteArray();
    }

    public static byte[] createStatusRequestExtension(CertificateStatusRequest statusRequest)
        throws IOException
    {
        if (statusRequest == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        statusRequest.encode(buf);

        return buf.toByteArray();
    }

    public static ServerNameList readServerNameExtension(byte[] extensionData)
        throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        ServerNameList serverNameList = ServerNameList.parse(buf);

        TlsProtocol.assertEmpty(buf);

        return serverNameList;
    }

    public static CertificateStatusRequest readStatusRequestExtension(byte[] extensionData)
        throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        CertificateStatusRequest statusRequest = CertificateStatusRequest.parse(buf);

        TlsProtocol.assertEmpty(buf);

        return statusRequest;
    }
}
