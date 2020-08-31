package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

public class TlsExtensionsUtils
{
    public static final Integer EXT_application_layer_protocol_negotiation = Integers.valueOf(ExtensionType.application_layer_protocol_negotiation);
    public static final Integer EXT_certificate_authorities = Integers.valueOf(ExtensionType.certificate_authorities);
    public static final Integer EXT_client_certificate_type = Integers.valueOf(ExtensionType.client_certificate_type);
    public static final Integer EXT_client_certificate_url = Integers.valueOf(ExtensionType.client_certificate_url);
    public static final Integer EXT_cookie = Integers.valueOf(ExtensionType.cookie);
    public static final Integer EXT_early_data = Integers.valueOf(ExtensionType.early_data);
    public static final Integer EXT_ec_point_formats = Integers.valueOf(ExtensionType.ec_point_formats);
    public static final Integer EXT_encrypt_then_mac = Integers.valueOf(ExtensionType.encrypt_then_mac);
    public static final Integer EXT_extended_master_secret = Integers.valueOf(ExtensionType.extended_master_secret);
    public static final Integer EXT_heartbeat = Integers.valueOf(ExtensionType.heartbeat);
    public static final Integer EXT_key_share = Integers.valueOf(ExtensionType.key_share);
    public static final Integer EXT_max_fragment_length = Integers.valueOf(ExtensionType.max_fragment_length);
    public static final Integer EXT_oid_filters = Integers.valueOf(ExtensionType.oid_filters);
    public static final Integer EXT_padding = Integers.valueOf(ExtensionType.padding);
    public static final Integer EXT_post_handshake_auth = Integers.valueOf(ExtensionType.post_handshake_auth);
    public static final Integer EXT_pre_shared_key = Integers.valueOf(ExtensionType.pre_shared_key);
    public static final Integer EXT_psk_key_exchange_modes = Integers.valueOf(ExtensionType.psk_key_exchange_modes);
    public static final Integer EXT_record_size_limit = Integers.valueOf(ExtensionType.record_size_limit);
    public static final Integer EXT_server_certificate_type = Integers.valueOf(ExtensionType.server_certificate_type);
    public static final Integer EXT_server_name = Integers.valueOf(ExtensionType.server_name);
    public static final Integer EXT_signature_algorithms = Integers.valueOf(ExtensionType.signature_algorithms);
    public static final Integer EXT_signature_algorithms_cert = Integers.valueOf(ExtensionType.signature_algorithms_cert);
    public static final Integer EXT_status_request = Integers.valueOf(ExtensionType.status_request);
    public static final Integer EXT_status_request_v2 = Integers.valueOf(ExtensionType.status_request_v2);
    public static final Integer EXT_supported_groups = Integers.valueOf(ExtensionType.supported_groups);
    public static final Integer EXT_supported_versions = Integers.valueOf(ExtensionType.supported_versions);
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

    public static void addCertificateAuthoritiesExtension(Hashtable extensions, Vector authorities) throws IOException
    {
        extensions.put(EXT_certificate_authorities, createCertificateAuthoritiesExtension(authorities));
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

    public static void addCookieExtension(Hashtable extensions, byte[] cookie) throws IOException
    {
        extensions.put(EXT_cookie, createCookieExtension(cookie));
    }

    public static void addEarlyDataIndication(Hashtable extensions)
    {
        extensions.put(EXT_early_data, createEarlyDataIndication());
    }

    public static void addEarlyDataMaxSize(Hashtable extensions, long maxSize) throws IOException
    {
        extensions.put(EXT_early_data, createEarlyDataMaxSize(maxSize));
    }

    public static void addEmptyExtensionData(Hashtable extensions, Integer extType)
    {
        extensions.put(extType, createEmptyExtensionData());
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

    public static void addKeyShareClientHello(Hashtable extensions, Vector clientShares)
        throws IOException
    {
        extensions.put(EXT_key_share, createKeyShareClientHello(clientShares));
    }

    public static void addKeyShareHelloRetryRequest(Hashtable extensions, int namedGroup)
        throws IOException
    {
        extensions.put(EXT_key_share, createKeyShareHelloRetryRequest(namedGroup));
    }

    public static void addKeyShareServerHello(Hashtable extensions, KeyShareEntry serverShare)
        throws IOException
    {
        extensions.put(EXT_key_share, createKeyShareServerHello(serverShare));
    }

    public static void addMaxFragmentLengthExtension(Hashtable extensions, short maxFragmentLength)
        throws IOException
    {
        extensions.put(EXT_max_fragment_length, createMaxFragmentLengthExtension(maxFragmentLength));
    }

    public static void addOIDFiltersExtension(Hashtable extensions, Hashtable filters) throws IOException
    {
        extensions.put(EXT_oid_filters, createOIDFiltersExtension(filters));
    }

    public static void addPaddingExtension(Hashtable extensions, int dataLength)
        throws IOException
    {
        extensions.put(EXT_padding, createPaddingExtension(dataLength));
    }

    public static void addPostHandshakeAuthExtension(Hashtable extensions)
    {
        extensions.put(EXT_post_handshake_auth, createPostHandshakeAuthExtension());
    }

    public static void addPreSharedKeyClientHello(Hashtable extensions, OfferedPsks offeredPsks)
        throws IOException
    {
        extensions.put(EXT_pre_shared_key, createPreSharedKeyClientHello(offeredPsks));
    }

    public static void addPreSharedKeyServerHello(Hashtable extensions, int selectedIdentity)
        throws IOException
    {
        extensions.put(EXT_pre_shared_key, createPreSharedKeyServerHello(selectedIdentity));
    }

    public static void addPSKKeyExchangeModesExtension(Hashtable extensions, short[] modes)
        throws IOException
    {
        extensions.put(EXT_psk_key_exchange_modes, createPSKKeyExchangeModesExtension(modes));
    }

    public static void addRecordSizeLimitExtension(Hashtable extensions, int recordSizeLimit)
        throws IOException
    {
        extensions.put(EXT_record_size_limit, createRecordSizeLimitExtension(recordSizeLimit));
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

    public static void addServerNameExtensionClient(Hashtable extensions, Vector serverNameList)
        throws IOException
    {
        extensions.put(EXT_server_name, createServerNameExtensionClient(serverNameList));
    }

    public static void addServerNameExtensionServer(Hashtable extensions)
        throws IOException
    {
        extensions.put(EXT_server_name, createServerNameExtensionServer());
    }

    public static void addSignatureAlgorithmsExtension(Hashtable extensions, Vector supportedSignatureAlgorithms)
        throws IOException
    {
        extensions.put(EXT_signature_algorithms, createSignatureAlgorithmsExtension(supportedSignatureAlgorithms));
    }

    public static void addSignatureAlgorithmsCertExtension(Hashtable extensions, Vector supportedSignatureAlgorithms)
        throws IOException
    {
        extensions.put(EXT_signature_algorithms_cert, createSignatureAlgorithmsCertExtension(supportedSignatureAlgorithms));
    }

    public static void addStatusRequestExtension(Hashtable extensions, CertificateStatusRequest statusRequest)
        throws IOException
    {
        extensions.put(EXT_status_request, createStatusRequestExtension(statusRequest));
    }

    public static void addStatusRequestV2Extension(Hashtable extensions, Vector statusRequestV2)
        throws IOException
    {
        extensions.put(EXT_status_request_v2, createStatusRequestV2Extension(statusRequestV2));
    }

    public static void addSupportedGroupsExtension(Hashtable extensions, Vector namedGroups) throws IOException
    {
        extensions.put(EXT_supported_groups, createSupportedGroupsExtension(namedGroups));
    }

    public static void addSupportedPointFormatsExtension(Hashtable extensions, short[] ecPointFormats)
        throws IOException
    {
        extensions.put(EXT_ec_point_formats, createSupportedPointFormatsExtension(ecPointFormats));
    }

    public static void addSupportedVersionsExtensionClient(Hashtable extensions, ProtocolVersion[] versions) throws IOException
    {
        extensions.put(EXT_supported_versions, createSupportedVersionsExtensionClient(versions));
    }

    public static void addSupportedVersionsExtensionServer(Hashtable extensions, ProtocolVersion selectedVersion) throws IOException
    {
        extensions.put(EXT_supported_versions, createSupportedVersionsExtensionServer(selectedVersion));
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

    public static Vector getCertificateAuthoritiesExtension(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_certificate_authorities);
        return extensionData == null ? null : readCertificateAuthoritiesExtension(extensionData);
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

    public static byte[] getCookieExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_cookie);
        return extensionData == null ? null : readCookieExtension(extensionData);
    }

    public static long getEarlyDataMaxSize(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_early_data);
        return extensionData == null ? -1L : readEarlyDataMaxSize(extensionData);
    }

    public static HeartbeatExtension getHeartbeatExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_heartbeat);
        return extensionData == null ? null : readHeartbeatExtension(extensionData);
    }

    public static Vector getKeyShareClientHello(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_key_share);
        return extensionData == null ? null : readKeyShareClientHello(extensionData);
    }

    public static int getKeyShareHelloRetryRequest(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_key_share);
        return extensionData == null ? -1 : readKeyShareHelloRetryRequest(extensionData);
    }

    public static KeyShareEntry getKeyShareServerHello(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_key_share);
        return extensionData == null ? null : readKeyShareServerHello(extensionData);
    }

    public static short getMaxFragmentLengthExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_max_fragment_length);
        return extensionData == null ? -1 : readMaxFragmentLengthExtension(extensionData);
    }

    public static Hashtable getOIDFiltersExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_oid_filters);
        return extensionData == null ? null : readOIDFiltersExtension(extensionData);
    }

    public static int getPaddingExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_padding);
        return extensionData == null ? -1 : readPaddingExtension(extensionData);
    }

    public static OfferedPsks getPreSharedKeyClientHello(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_pre_shared_key);
        return extensionData == null ? null : readPreSharedKeyClientHello(extensionData);
    }

    public static int getPreSharedKeyServerHello(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_pre_shared_key);
        return extensionData == null ? -1 : readPreSharedKeyServerHello(extensionData);
    }

    public static short[] getPSKKeyExchangeModesExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_psk_key_exchange_modes);
        return extensionData == null ? null : readPSKKeyExchangeModesExtension(extensionData);
    }

    public static int getRecordSizeLimitExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_record_size_limit);
        return extensionData == null ? -1 : readRecordSizeLimitExtension(extensionData);
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

    public static Vector getServerNameExtensionClient(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_server_name);
        return extensionData == null ? null : readServerNameExtensionClient(extensionData);
    }

    public static Vector getSignatureAlgorithmsExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_signature_algorithms);
        return extensionData == null ? null : readSignatureAlgorithmsExtension(extensionData);
    }

    public static Vector getSignatureAlgorithmsCertExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_signature_algorithms_cert);
        return extensionData == null ? null : readSignatureAlgorithmsCertExtension(extensionData);
    }

    public static CertificateStatusRequest getStatusRequestExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_status_request);
        return extensionData == null ? null : readStatusRequestExtension(extensionData);
    }

    public static Vector getStatusRequestV2Extension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_status_request_v2);
        return extensionData == null ? null : readStatusRequestV2Extension(extensionData);
    }

    public static int[] getSupportedGroupsExtension(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_supported_groups);
        return extensionData == null ? null : readSupportedGroupsExtension(extensionData);
    }

    public static short[] getSupportedPointFormatsExtension(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_ec_point_formats);
        return extensionData == null ? null : readSupportedPointFormatsExtension(extensionData);
    }

    public static ProtocolVersion[] getSupportedVersionsExtensionClient(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_supported_versions);
        return extensionData == null ? null : readSupportedVersionsExtensionClient(extensionData);
    }

    public static ProtocolVersion getSupportedVersionsExtensionServer(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_supported_versions);
        return extensionData == null ? null : readSupportedVersionsExtensionServer(extensionData);
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

    public static boolean hasEarlyDataIndication(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_early_data);
        return extensionData == null ? false : readEarlyDataIndication(extensionData);
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

    public static boolean hasServerNameExtensionServer(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_server_name);
        return extensionData == null ? false : readServerNameExtensionServer(extensionData);
    }

    public static boolean hasPostHandshakeAuthExtension(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_post_handshake_auth);
        return extensionData == null ? false : readPostHandshakeAuthExtension(extensionData);
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

    public static byte[] createCertificateAuthoritiesExtension(Vector authorities) throws IOException
    {
        if (null == authorities || authorities.isEmpty())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        // Placeholder for length
        TlsUtils.writeUint16(0, buf);

        for (int i = 0; i < authorities.size(); ++i)
        {
            X500Name authority = (X500Name)authorities.elementAt(i);
            byte[] derEncoding = authority.getEncoded(ASN1Encoding.DER);
            TlsUtils.writeOpaque16(derEncoding, buf);
        }

        int length = buf.size() - 2;
        TlsUtils.checkUint16(length);
        byte[] extensionData = buf.toByteArray();
        TlsUtils.writeUint16(length, extensionData, 0);
        return extensionData;
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

    public static byte[] createCookieExtension(byte[] cookie) throws IOException
    {
        if (cookie == null || cookie.length < 1 || cookie.length >= (1 << 16))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return TlsUtils.encodeOpaque16(cookie);
    }

    public static byte[] createEarlyDataIndication()
    {
        return createEmptyExtensionData();
    }

    public static byte[] createEarlyDataMaxSize(long maxSize) throws IOException
    {
        return TlsUtils.encodeUint32(maxSize);
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

    public static byte[] createKeyShareClientHello(Vector clientShares)
        throws IOException
    {
        if (clientShares == null || clientShares.isEmpty())
        {
            return TlsUtils.encodeUint16(0);
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        // Placeholder for length
        TlsUtils.writeUint16(0, buf);

        for (int i = 0; i < clientShares.size(); ++i)
        {
            KeyShareEntry clientShare = (KeyShareEntry)clientShares.elementAt(i);

            clientShare.encode(buf);
        }

        int length = buf.size() - 2;
        TlsUtils.checkUint16(length);
        byte[] extensionData = buf.toByteArray();
        TlsUtils.writeUint16(length, extensionData, 0);
        return extensionData;
    }

    public static byte[] createKeyShareHelloRetryRequest(int namedGroup)
        throws IOException
    {
        return TlsUtils.encodeUint16(namedGroup);
    }

    public static byte[] createKeyShareServerHello(KeyShareEntry serverShare)
        throws IOException
    {
        if (serverShare == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        serverShare.encode(buf);

        return buf.toByteArray();
    }

    public static byte[] createMaxFragmentLengthExtension(short maxFragmentLength)
        throws IOException
    {
        return TlsUtils.encodeUint8(maxFragmentLength);
    }

    public static byte[] createOIDFiltersExtension(Hashtable filters) throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        // Placeholder for length
        TlsUtils.writeUint16(0, buf);

        if (null != filters)
        {
            Enumeration keys = filters.keys();
            while (keys.hasMoreElements())
            {
                ASN1ObjectIdentifier certificateExtensionOID = (ASN1ObjectIdentifier)keys.nextElement();
                byte[] certificateExtensionValues = (byte[])filters.get(certificateExtensionOID);

                if (null == certificateExtensionOID || null == certificateExtensionValues)
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                byte[] derEncoding = certificateExtensionOID.getEncoded(ASN1Encoding.DER);
                TlsUtils.writeOpaque8(derEncoding, buf);

                TlsUtils.writeOpaque16(certificateExtensionValues, buf);
            }
        }

        int length = buf.size() - 2;
        TlsUtils.checkUint16(length);
        byte[] extensionData = buf.toByteArray();
        TlsUtils.writeUint16(length, extensionData, 0);
        return extensionData;
    }

    public static byte[] createPaddingExtension(int dataLength)
        throws IOException
    {
        TlsUtils.checkUint16(dataLength);
        return new byte[dataLength];
    }

    public static byte[] createPostHandshakeAuthExtension()
    {
        return createEmptyExtensionData();
    }

    public static byte[] createPreSharedKeyClientHello(OfferedPsks offeredPsks) throws IOException
    {
        if (offeredPsks == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        offeredPsks.encode(buf);

        return buf.toByteArray();
    }

    public static byte[] createPreSharedKeyServerHello(int selectedIdentity) throws IOException
    {
        return TlsUtils.encodeUint16(selectedIdentity);
    }

    public static byte[] createPSKKeyExchangeModesExtension(short[] modes) throws IOException
    {
        if (modes == null || modes.length < 1 || modes.length > 255)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return TlsUtils.encodeUint8ArrayWithUint8Length(modes);
    }

    public static byte[] createRecordSizeLimitExtension(int recordSizeLimit)
        throws IOException
    {
        if (recordSizeLimit < 64)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return TlsUtils.encodeUint16(recordSizeLimit);
    }

    public static byte[] createServerNameExtensionClient(Vector serverNameList)
        throws IOException
    {
        if (serverNameList == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        new ServerNameList(serverNameList).encode(buf);

        return buf.toByteArray();
    }

    public static byte[] createServerNameExtensionServer()
    {
        return createEmptyExtensionData();
    }

    public static byte[] createSignatureAlgorithmsExtension(Vector supportedSignatureAlgorithms)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        TlsUtils.encodeSupportedSignatureAlgorithms(supportedSignatureAlgorithms, buf);

        return buf.toByteArray();
    }

    public static byte[] createSignatureAlgorithmsCertExtension(Vector supportedSignatureAlgorithms)
        throws IOException
    {
        return createSignatureAlgorithmsExtension(supportedSignatureAlgorithms);
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

    public static byte[] createStatusRequestV2Extension(Vector statusRequestV2)
        throws IOException
    {
        if (statusRequestV2 == null || statusRequestV2.isEmpty())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        // Placeholder for length
        TlsUtils.writeUint16(0, buf);

        for (int i = 0; i < statusRequestV2.size(); ++i)
        {
            CertificateStatusRequestItemV2 entry = (CertificateStatusRequestItemV2)statusRequestV2.elementAt(i);
            entry.encode(buf);
        }

        int length = buf.size() - 2;
        TlsUtils.checkUint16(length);
        byte[] extensionData = buf.toByteArray();
        TlsUtils.writeUint16(length, extensionData, 0);
        return extensionData;
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

    public static byte[] createSupportedPointFormatsExtension(short[] ecPointFormats) throws IOException
    {
        if (ecPointFormats == null || !Arrays.contains(ecPointFormats, ECPointFormat.uncompressed))
        {
            /*
             * RFC 4492 5.1. If the Supported Point Formats Extension is indeed sent, it MUST
             * contain the value 0 (uncompressed) as one of the items in the list of point formats.
             */

            // NOTE: We add it at the start (highest preference)
            ecPointFormats = Arrays.prepend(ecPointFormats, ECPointFormat.uncompressed);
        }

        return TlsUtils.encodeUint8ArrayWithUint8Length(ecPointFormats);
    }

    public static byte[] createSupportedVersionsExtensionClient(ProtocolVersion[] versions) throws IOException
    {
        if (versions == null || versions.length < 1 || versions.length > 127)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        int count = versions.length;
        byte[] data = new byte[1 + count * 2];
        TlsUtils.writeUint8(count * 2, data, 0);
        for (int i = 0; i < count; ++i)
        {
            TlsUtils.writeVersion((ProtocolVersion)versions[i], data, 1 + i * 2);
        }
        return data;
    }

    public static byte[] createSupportedVersionsExtensionServer(ProtocolVersion selectedVersion) throws IOException
    {
        return TlsUtils.encodeVersion(selectedVersion);
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

        if (trustedAuthoritiesList != null)
        {
            for (int i = 0; i < trustedAuthoritiesList.size(); ++i)
            {
                TrustedAuthority entry = (TrustedAuthority)trustedAuthoritiesList.elementAt(i);
                entry.encode(buf);
            }
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

    public static Vector readCertificateAuthoritiesExtension(byte[] extensionData) throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }
        if (extensionData.length < 5)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        int length = TlsUtils.readUint16(buf);
        if (length != (extensionData.length - 2))
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        Vector authorities = new Vector();
        while (buf.available() > 0)
        {
            byte[] derEncoding = TlsUtils.readOpaque16(buf, 1);
            ASN1Primitive asn1 = TlsUtils.readDERObject(derEncoding);
            authorities.addElement(X500Name.getInstance(asn1));
        }
        return authorities;
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

    public static byte[] readCookieExtension(byte[] extensionData) throws IOException
    {
        return TlsUtils.decodeOpaque16(extensionData, 1);
    }

    public static boolean readEarlyDataIndication(byte[] extensionData) throws IOException
    {
        return readEmptyExtensionData(extensionData);
    }

    public static long readEarlyDataMaxSize(byte[] extensionData) throws IOException
    {
        return TlsUtils.decodeUint32(extensionData);
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

    public static Vector readKeyShareClientHello(byte[] extensionData)
        throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        /*
         * TODO[tls13] Clients MUST NOT offer multiple KeyShareEntry values for the same group.
         * Clients MUST NOT offer any KeyShareEntry values for groups not listed in the client's
         * "supported_groups" extension. Servers MAY check for violations of these rules and abort
         * the handshake with an "illegal_parameter" alert if one is violated.
         */

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        int length = TlsUtils.readUint16(buf);
        if (length != (extensionData.length - 2))
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        Vector clientShares = new Vector();
        while (buf.available() > 0)
        {
            KeyShareEntry clientShare = KeyShareEntry.parse(buf);

            clientShares.addElement(clientShare);
        }
        return clientShares;
    }

    public static int readKeyShareHelloRetryRequest(byte[] extensionData)
        throws IOException
    {
        return TlsUtils.decodeUint16(extensionData);
    }

    public static KeyShareEntry readKeyShareServerHello(byte[] extensionData)
        throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        KeyShareEntry serverShare = KeyShareEntry.parse(buf);

        TlsProtocol.assertEmpty(buf);

        return serverShare;
    }

    public static short readMaxFragmentLengthExtension(byte[] extensionData)
        throws IOException
    {
        return TlsUtils.decodeUint8(extensionData);
    }

    public static Hashtable readOIDFiltersExtension(byte[] extensionData) throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }
        if (extensionData.length < 2)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        int length = TlsUtils.readUint16(buf);
        if (length != (extensionData.length - 2))
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        Hashtable filters = new Hashtable();
        while (buf.available() > 0)
        {
            byte[] derEncoding = TlsUtils.readOpaque8(buf, 1);
            ASN1Primitive asn1 = TlsUtils.readDERObject(derEncoding);
            ASN1ObjectIdentifier certificateExtensionOID = ASN1ObjectIdentifier.getInstance(asn1);

            if (filters.containsKey(certificateExtensionOID))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            byte[] certificateExtensionValues = TlsUtils.readOpaque16(buf);

            filters.put(certificateExtensionOID, certificateExtensionValues);
        }
        return filters;
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

    public static boolean readPostHandshakeAuthExtension(byte[] extensionData) throws IOException
    {
        return readEmptyExtensionData(extensionData);
    }

    public static OfferedPsks readPreSharedKeyClientHello(byte[] extensionData) throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        OfferedPsks offeredPsks = OfferedPsks.parse(buf);

        TlsProtocol.assertEmpty(buf);

        return offeredPsks;
    }

    public static int readPreSharedKeyServerHello(byte[] extensionData) throws IOException
    {
        return TlsUtils.decodeUint16(extensionData);
    }

    public static short[] readPSKKeyExchangeModesExtension(byte[] extensionData) throws IOException
    {
        short[] modes = TlsUtils.decodeUint8ArrayWithUint8Length(extensionData);
        if (modes.length < 1)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        return modes;
    }

    public static int readRecordSizeLimitExtension(byte[] extensionData)
        throws IOException
    {
        int recordSizeLimit = TlsUtils.decodeUint16(extensionData);
        if (recordSizeLimit < 64)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return recordSizeLimit;
    }

    public static Vector readServerNameExtensionClient(byte[] extensionData)
        throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        ServerNameList serverNameList = ServerNameList.parse(buf);

        TlsProtocol.assertEmpty(buf);

        return serverNameList.getServerNameList();
    }

    public static boolean readServerNameExtensionServer(byte[] extensionData) throws IOException
    {
        return readEmptyExtensionData(extensionData);
    }

    public static Vector readSignatureAlgorithmsExtension(byte[] extensionData)
        throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        Vector supported_signature_algorithms = TlsUtils.parseSupportedSignatureAlgorithms(buf);

        TlsProtocol.assertEmpty(buf);

        return supported_signature_algorithms;
    }

    public static Vector readSignatureAlgorithmsCertExtension(byte[] extensionData)
        throws IOException
    {
        return readSignatureAlgorithmsExtension(extensionData);
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

    public static Vector readStatusRequestV2Extension(byte[] extensionData)
        throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }
        if (extensionData.length < 3)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        int length = TlsUtils.readUint16(buf);
        if (length != (extensionData.length - 2))
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        Vector statusRequestV2 = new Vector();
        while (buf.available() > 0)
        {
            CertificateStatusRequestItemV2 entry = CertificateStatusRequestItemV2.parse(buf);
            statusRequestV2.add(entry);
        }
        return statusRequestV2;
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

    public static short[] readSupportedPointFormatsExtension(byte[] extensionData) throws IOException
    {
        short[] ecPointFormats = TlsUtils.decodeUint8ArrayWithUint8Length(extensionData);
        if (!Arrays.contains(ecPointFormats, ECPointFormat.uncompressed))
        {
            /*
             * RFC 4492 5.1. If the Supported Point Formats Extension is indeed sent, it MUST
             * contain the value 0 (uncompressed) as one of the items in the list of point formats.
             */
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        return ecPointFormats;
    }

    public static ProtocolVersion[] readSupportedVersionsExtensionClient(byte[] extensionData) throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }
        if (extensionData.length < 3 || extensionData.length > 255 || (extensionData.length & 1) == 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        int length = TlsUtils.readUint8(extensionData, 0);
        if (length != (extensionData.length - 1))
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        int count = length / 2;
        ProtocolVersion[] versions = new ProtocolVersion[count];
        for (int i = 0; i < count; ++i)
        {
            versions[i] = TlsUtils.readVersion(extensionData, 1 + i * 2);
        }
        return versions;
    }

    public static ProtocolVersion readSupportedVersionsExtensionServer(byte[] extensionData) throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }
        if (extensionData.length != 2)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        return TlsUtils.readVersion(extensionData, 0);
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
        if (extensionData.length < 2)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
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
