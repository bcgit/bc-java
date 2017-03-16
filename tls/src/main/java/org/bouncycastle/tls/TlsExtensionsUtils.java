package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.util.Integers;

public class TlsExtensionsUtils
{
    public static final Integer EXT_encrypt_then_mac = Integers.valueOf(ExtensionType.encrypt_then_mac);
    public static final Integer EXT_extended_master_secret = Integers.valueOf(ExtensionType.extended_master_secret);
    public static final Integer EXT_heartbeat = Integers.valueOf(ExtensionType.heartbeat);
    public static final Integer EXT_max_fragment_length = Integers.valueOf(ExtensionType.max_fragment_length);
    public static final Integer EXT_padding = Integers.valueOf(ExtensionType.padding);
    public static final Integer EXT_server_name = Integers.valueOf(ExtensionType.server_name);
    public static final Integer EXT_status_request = Integers.valueOf(ExtensionType.status_request);
    public static final Integer EXT_truncated_hmac = Integers.valueOf(ExtensionType.truncated_hmac);

    public static Hashtable ensureExtensionsInitialised(Hashtable extensions)
    {
        return extensions == null ? new Hashtable() : extensions;
    }

    public static void addEncryptThenMACExtension(Hashtable extensions)
    {
        extensions.put(EXT_encrypt_then_mac, createEncryptThenMACExtension());
    }

    public static void addExtendedMasterSecretExtension(Hashtable extensions)
    {
        extensions.put(EXT_extended_master_secret, createExtendedMasterSecretExtension());
    }

    public static void addHeartbeatExtension(Hashtable extensions, HeartbeatExtension heartbeatExtension)
        throws IOException
    {
        extensions.put(EXT_heartbeat, createHeartbeatExtension(heartbeatExtension));
    }

    public static void addMaxFragmentLengthExtension(Hashtable extensions, short maxFragmentLength)
        throws IOException
    {
        extensions.put(EXT_max_fragment_length, createMaxFragmentLengthExtension(maxFragmentLength));
    }

    public static void addPaddingExtension(Hashtable extensions, int dataLength)
        throws IOException
    {
        extensions.put(EXT_padding, createPaddingExtension(dataLength));
    }

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

    public static void addTruncatedHMacExtension(Hashtable extensions)
    {
        extensions.put(EXT_truncated_hmac, createTruncatedHMacExtension());
    }

    public static HeartbeatExtension getHeartbeatExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_heartbeat);
        return extensionData == null ? null : readHeartbeatExtension(extensionData);
    }

    public static short getMaxFragmentLengthExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_max_fragment_length);
        return extensionData == null ? -1 : readMaxFragmentLengthExtension(extensionData);
    }

    public static int getPaddingExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_padding);
        return extensionData == null ? -1 : readPaddingExtension(extensionData);
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

    public static boolean hasEncryptThenMACExtension(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_encrypt_then_mac);
        return extensionData == null ? false : readEncryptThenMACExtension(extensionData);
    }

    public static boolean hasExtendedMasterSecretExtension(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_extended_master_secret);
        return extensionData == null ? false : readExtendedMasterSecretExtension(extensionData);
    }

    public static boolean hasTruncatedHMacExtension(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_truncated_hmac);
        return extensionData == null ? false : readTruncatedHMacExtension(extensionData);
    }

    public static byte[] createEmptyExtensionData()
    {
        return TlsUtils.EMPTY_BYTES;
    }

    public static byte[] createEncryptThenMACExtension()
    {
        return createEmptyExtensionData();
    }

    public static byte[] createExtendedMasterSecretExtension()
    {
        return createEmptyExtensionData();
    }

    public static byte[] createHeartbeatExtension(HeartbeatExtension heartbeatExtension)
        throws IOException
    {
        if (heartbeatExtension == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        heartbeatExtension.encode(buf);

        return buf.toByteArray();
    }

    public static byte[] createMaxFragmentLengthExtension(short maxFragmentLength)
        throws IOException
    {
        TlsUtils.checkUint8(maxFragmentLength);

        byte[] extensionData = new byte[1];
        TlsUtils.writeUint8(maxFragmentLength, extensionData, 0);
        return extensionData;
    }

    public static byte[] createPaddingExtension(int dataLength)
        throws IOException
    {
        TlsUtils.checkUint16(dataLength);
        return new byte[dataLength];
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

    public static byte[] createTruncatedHMacExtension()
    {
        return createEmptyExtensionData();
    }

    private static boolean readEmptyExtensionData(byte[] extensionData) throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        if (extensionData.length != 0)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return true;
    }

    public static boolean readEncryptThenMACExtension(byte[] extensionData) throws IOException
    {
        return readEmptyExtensionData(extensionData);
    }

    public static boolean readExtendedMasterSecretExtension(byte[] extensionData) throws IOException
    {
        return readEmptyExtensionData(extensionData);
    }

    public static HeartbeatExtension readHeartbeatExtension(byte[] extensionData)
        throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        HeartbeatExtension heartbeatExtension = HeartbeatExtension.parse(buf);

        TlsProtocol.assertEmpty(buf);

        return heartbeatExtension;
    }

    public static short readMaxFragmentLengthExtension(byte[] extensionData)
        throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        if (extensionData.length != 1)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        return TlsUtils.readUint8(extensionData, 0);
    }

    public static int readPaddingExtension(byte[] extensionData)
        throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }
        for (int i = 0; i < extensionData.length; ++i)
        {
            if (extensionData[i] != 0)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
        return extensionData.length;
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

    public static boolean readTruncatedHMacExtension(byte[] extensionData) throws IOException
    {
        return readEmptyExtensionData(extensionData);
    }
}
