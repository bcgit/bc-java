package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.util.Integers;

public class TlsExtensionsUtils
{
    public static final Integer EXT_application_layer_protocol_negotiation = Integers.valueOf(ExtensionType.application_layer_protocol_negotiation);
    public static final Integer EXT_client_certificate_type = Integers.valueOf(ExtensionType.client_certificate_type);
    public static final Integer EXT_client_certificate_url = Integers.valueOf(ExtensionType.client_certificate_url);
    public static final Integer EXT_encrypt_then_mac = Integers.valueOf(ExtensionType.encrypt_then_mac);
    public static final Integer EXT_extended_master_secret = Integers.valueOf(ExtensionType.extended_master_secret);
    public static final Integer EXT_heartbeat = Integers.valueOf(ExtensionType.heartbeat);
    public static final Integer EXT_max_fragment_length = Integers.valueOf(ExtensionType.max_fragment_length);
    public static final Integer EXT_padding = Integers.valueOf(ExtensionType.padding);
    public static final Integer EXT_server_certificate_type = Integers.valueOf(ExtensionType.server_certificate_type);
    public static final Integer EXT_server_name = Integers.valueOf(ExtensionType.server_name);
    public static final Integer EXT_status_request = Integers.valueOf(ExtensionType.status_request);
    public static final Integer EXT_supported_groups = Integers.valueOf(ExtensionType.supported_groups);
    public static final Integer EXT_truncated_hmac = Integers.valueOf(ExtensionType.truncated_hmac);
    public static final Integer EXT_trusted_ca_keys = Integers.valueOf(ExtensionType.trusted_ca_keys);

    public static Hashtable ensureExtensionsInitialised(Hashtable extensions)
    {
        return extensions == null ? new Hashtable() : extensions;
    }

    /**
     * @param protocolNameList a {@link Vector} of {@link ProtocolName}
     */
    public static void addALPNExtensionClient(Hashtable extensions, Vector protocolNameList) throws IOException
    {
        extensions.put(EXT_application_layer_protocol_negotiation, createALPNExtensionClient(protocolNameList));
    }

    public static void addALPNExtensionServer(Hashtable extensions, ProtocolName protocolName) throws IOException
    {
        extensions.put(EXT_application_layer_protocol_negotiation, createALPNExtensionServer(protocolName));
    }

    public static void addClientCertificateTypeExtensionClient(Hashtable extensions, short[] certificateTypes)
        throws IOException
    {
        extensions.put(EXT_client_certificate_type, createCertificateTypeExtensionClient(certificateTypes));
    }

    public static void addClientCertificateTypeExtensionServer(Hashtable extensions, short certificateType)
        throws IOException
    {
        extensions.put(EXT_client_certificate_type, createCertificateTypeExtensionServer(certificateType));
    }

    public static void addClientCertificateURLExtension(Hashtable extensions)
    {
        extensions.put(EXT_client_certificate_url, createClientCertificateURLExtension());
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

    public static void addServerCertificateTypeExtensionClient(Hashtable extensions, short[] certificateTypes)
        throws IOException
    {
        extensions.put(EXT_server_certificate_type, createCertificateTypeExtensionClient(certificateTypes));
    }

    public static void addServerCertificateTypeExtensionServer(Hashtable extensions, short certificateType)
        throws IOException
    {
        extensions.put(EXT_server_certificate_type, createCertificateTypeExtensionServer(certificateType));
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

    public static void addSupportedGroupsExtension(Hashtable extensions, Vector namedGroups) throws IOException
    {
        extensions.put(EXT_supported_groups, createSupportedGroupsExtension(namedGroups));
    }

    public static void addTruncatedHMacExtension(Hashtable extensions)
    {
        extensions.put(EXT_truncated_hmac, createTruncatedHMacExtension());
    }

    public static void addTrustedCAKeysExtensionClient(Hashtable extensions, Vector trustedAuthoritiesList)
        throws IOException
    {
        extensions.put(EXT_trusted_ca_keys, createTrustedCAKeysExtensionClient(trustedAuthoritiesList));
    }

    public static void addTrustedCAKeysExtensionServer(Hashtable extensions)
    {
        extensions.put(EXT_trusted_ca_keys, createTrustedCAKeysExtensionServer());
    }

    /**
     * @return a {@link Vector} of {@link ProtocolName}
     */
    public static Vector getALPNExtensionClient(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_application_layer_protocol_negotiation);
        return extensionData == null ? null : readALPNExtensionClient(extensionData);
    }

    public static ProtocolName getALPNExtensionServer(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_application_layer_protocol_negotiation);
        return extensionData == null ? null : readALPNExtensionServer(extensionData);
    }

    public static short[] getClientCertificateTypeExtensionClient(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_client_certificate_type);
        return extensionData == null ? null : readCertificateTypeExtensionClient(extensionData);
    }

    public static short getClientCertificateTypeExtensionServer(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_client_certificate_type);
        return extensionData == null ? -1 : readCertificateTypeExtensionServer(extensionData);
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

    public static short[] getServerCertificateTypeExtensionClient(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_server_certificate_type);
        return extensionData == null ? null : readCertificateTypeExtensionClient(extensionData);
    }

    public static short getServerCertificateTypeExtensionServer(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_server_certificate_type);
        return extensionData == null ? -1 : readCertificateTypeExtensionServer(extensionData);
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

    public static int[] getSupportedGroupsExtension(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_supported_groups);
        return extensionData == null ? null : readSupportedGroupsExtension(extensionData);
    }

    public static Vector getTrustedCAKeysExtensionClient(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_trusted_ca_keys);
        return extensionData == null ? null : readTrustedCAKeysExtensionClient(extensionData);
    }

    public static boolean hasClientCertificateURLExtension(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_client_certificate_url);
        return extensionData == null ? false : readClientCertificateURLExtension(extensionData);
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

    public static boolean hasTrustedCAKeysExtensionServer(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_trusted_ca_keys);
        return extensionData == null ? false : readTrustedCAKeysExtensionServer(extensionData);
    }

    /**
     * @param protocolNameList a {@link Vector} of {@link ProtocolName}
     */
    public static byte[] createALPNExtensionClient(Vector protocolNameList) throws IOException
    {
        if (protocolNameList == null || protocolNameList.size() < 1)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        // Placeholder for length
        TlsUtils.writeUint16(0, buf);

        for (int i = 0; i < protocolNameList.size(); ++i)
        {
            ProtocolName protocolName = (ProtocolName)protocolNameList.elementAt(i);

            protocolName.encode(buf);
        }

        int length = buf.size() - 2;
        TlsUtils.checkUint16(length);
        byte[] extensionData = buf.toByteArray();
        TlsUtils.writeUint16(length, extensionData, 0);
        return extensionData;
    }

    public static byte[] createALPNExtensionServer(ProtocolName protocolName) throws IOException
    {
        Vector protocol_name_list = new Vector();
        protocol_name_list.addElement(protocolName);

        return createALPNExtensionClient(protocol_name_list);
    }

    public static byte[] createCertificateTypeExtensionClient(short[] certificateTypes) throws IOException
    {
        if (certificateTypes == null || certificateTypes.length < 1 || certificateTypes.length > 255)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return TlsUtils.encodeUint8ArrayWithUint8Length(certificateTypes);
    }

    public static byte[] createCertificateTypeExtensionServer(short certificateType) throws IOException
    {
        return TlsUtils.encodeUint8(certificateType);
    }

    public static byte[] createClientCertificateURLExtension()
    {
        return createEmptyExtensionData();
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
        return TlsUtils.encodeUint8(maxFragmentLength);
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

    public static byte[] createSupportedGroupsExtension(Vector namedGroups) throws IOException
    {
        if (namedGroups == null || namedGroups.isEmpty())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        int count = namedGroups.size();
        int[] values = new int[count];
        for (int i = 0; i < count; ++i)
        {
            values[i] = ((Integer)namedGroups.elementAt(i)).intValue();
        }

        return TlsUtils.encodeUint16ArrayWithUint16Length(values);
    }

    public static byte[] createTruncatedHMacExtension()
    {
        return createEmptyExtensionData();
    }

    public static byte[] createTrustedCAKeysExtensionClient(Vector trustedAuthoritiesList)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        // Placeholder for length
        TlsUtils.writeUint16(0, buf);

        for (int i = 0; i < trustedAuthoritiesList.size(); ++i)
        {
            TrustedAuthority entry = (TrustedAuthority)trustedAuthoritiesList.elementAt(i);
            entry.encode(buf);
        }

        int length = buf.size() - 2;
        TlsUtils.checkUint16(length);
        byte[] extensionData = buf.toByteArray();
        TlsUtils.writeUint16(length, extensionData, 0);
        return extensionData;
    }

    public static byte[] createTrustedCAKeysExtensionServer()
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

    /**
     * @return a {@link Vector} of {@link ProtocolName}
     */
    public static Vector readALPNExtensionClient(byte[] extensionData) throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        int length = TlsUtils.readUint16(buf);
        if (length != (extensionData.length - 2))
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        Vector protocol_name_list = new Vector();
        while (buf.available() > 0)
        {
            ProtocolName protocolName = ProtocolName.parse(buf);

            protocol_name_list.addElement(protocolName);
        }
        return protocol_name_list;
    }

    public static ProtocolName readALPNExtensionServer(byte[] extensionData) throws IOException
    {
        Vector protocol_name_list = readALPNExtensionClient(extensionData);
        if (protocol_name_list.size() != 1)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        return (ProtocolName)protocol_name_list.elementAt(0);
    }

    public static short[] readCertificateTypeExtensionClient(byte[] extensionData) throws IOException
    {
        short[] certificateTypes = TlsUtils.decodeUint8ArrayWithUint8Length(extensionData);
        if (certificateTypes.length < 1)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        return certificateTypes;
    }

    public static short readCertificateTypeExtensionServer(byte[] extensionData) throws IOException
    {
        return TlsUtils.decodeUint8(extensionData);
    }

    public static boolean readClientCertificateURLExtension(byte[] extensionData) throws IOException
    {
        return readEmptyExtensionData(extensionData);
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
        return TlsUtils.decodeUint8(extensionData);
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

    public static int[] readSupportedGroupsExtension(byte[] extensionData) throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        int length = TlsUtils.readUint16(buf);
        if (length < 2 || (length & 1) != 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        int[] namedGroups = TlsUtils.readUint16Array(length / 2, buf);

        TlsProtocol.assertEmpty(buf);

        return namedGroups;
    }

    public static boolean readTruncatedHMacExtension(byte[] extensionData) throws IOException
    {
        return readEmptyExtensionData(extensionData);
    }

    public static Vector readTrustedCAKeysExtensionClient(byte[] extensionData) throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        int length = TlsUtils.readUint16(buf);
        if (length != (extensionData.length - 2))
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        Vector trusted_authorities_list = new Vector();
        while (buf.available() > 0)
        {
            TrustedAuthority entry = TrustedAuthority.parse(buf);
            trusted_authorities_list.addElement(entry);
        }
        return trusted_authorities_list;
    }

    public static boolean readTrustedCAKeysExtensionServer(byte[] extensionData) throws IOException
    {
        return readEmptyExtensionData(extensionData);
    }
}
