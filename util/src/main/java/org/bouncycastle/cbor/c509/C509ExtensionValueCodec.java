package org.bouncycastle.cbor.c509;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DisplayText;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;
import org.bouncycastle.cbor.CBORType;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Longs;

/**
 * The CBOR encodings of the registered extension values, Section 3.3 of
 * draft-ietf-cose-cbor-encoded-cert-20.
 * <p>
 * The two directions have deliberately different failure behaviour. Encoding
 * (DER to CBOR) returns null whenever the specific encoding cannot faithfully
 * represent the DER value - the caller then falls back to the generic
 * (extensionID: ~oid, extensionValue: bytes) form, which can carry anything.
 * Decoding (CBOR to DER) throws an IOException on anything malformed, since there
 * is nothing to fall back to.
 */
class C509ExtensionValueCodec
{
    /*
     * C509 General Names Registry, Section 8.13.
     */
    static final int GN_OTHER_NAME_MAC_ADDRESS = -3;
    static final int GN_OTHER_NAME_SMTP_UTF8_MAILBOX = -2;
    static final int GN_OTHER_NAME_HARDWARE_MODULE_NAME = -1;
    static final int GN_OTHER_NAME = 0;
    static final int GN_RFC822_NAME = 1;
    static final int GN_DNS_NAME = 2;
    static final int GN_DIRECTORY_NAME = 4;
    static final int GN_URI = 6;
    static final int GN_IP_ADDRESS = 7;
    static final int GN_REGISTERED_ID = 8;

    private static final ASN1ObjectIdentifier id_on = X509ObjectIdentifiers.id_pkix.branch("8");
    private static final ASN1ObjectIdentifier id_on_hardwareModuleName = id_on.branch("4");
    private static final ASN1ObjectIdentifier id_on_SmtpUTF8Mailbox = id_on.branch("9");
    private static final ASN1ObjectIdentifier id_on_MACAddress = id_on.branch("12");

    /*
     * C509 Extended Key Usages Registry, Section 8.12; C509 Certificate Policies
     * Registry, Section 8.9; C509 Policies Qualifiers Registry, Section 8.10; C509
     * Information Access Registry, Section 8.11.
     */
    private static final Map<Integer, ASN1ObjectIdentifier> ekuCodeToOid = new HashMap<Integer, ASN1ObjectIdentifier>();
    private static final Map<ASN1ObjectIdentifier, Integer> ekuOidToCode = new HashMap<ASN1ObjectIdentifier, Integer>();
    private static final Map<Integer, ASN1ObjectIdentifier> policyCodeToOid = new HashMap<Integer, ASN1ObjectIdentifier>();
    private static final Map<ASN1ObjectIdentifier, Integer> policyOidToCode = new HashMap<ASN1ObjectIdentifier, Integer>();
    private static final Map<Integer, ASN1ObjectIdentifier> accessCodeToOid = new HashMap<Integer, ASN1ObjectIdentifier>();
    private static final Map<ASN1ObjectIdentifier, Integer> accessOidToCode = new HashMap<ASN1ObjectIdentifier, Integer>();

    private static final ASN1ObjectIdentifier id_qt_cps = PolicyQualifierId.id_qt_cps;
    private static final ASN1ObjectIdentifier id_qt_unotice = PolicyQualifierId.id_qt_unotice;

    private static void registerTable(Map<Integer, ASN1ObjectIdentifier> byCode,
        Map<ASN1ObjectIdentifier, Integer> byOid, int code, ASN1ObjectIdentifier oid)
    {
        Integer boxed = Integers.valueOf(code);
        if (byCode.put(boxed, oid) != null || byOid.put(oid, boxed) != null)
        {
            throw new IllegalStateException("duplicate registry entry: " + code);
        }
    }

    private static void registerTable(Map<Integer, ASN1ObjectIdentifier> byCode,
        Map<ASN1ObjectIdentifier, Integer> byOid, int code, String oid)
    {
        registerTable(byCode, byOid, code, new ASN1ObjectIdentifier(oid));
    }

    static
    {
        // Figure 16: C509 Extended Key Usages
        registerTable(ekuCodeToOid, ekuOidToCode, 0, KeyPurposeId.anyExtendedKeyUsage.toOID());
        registerTable(ekuCodeToOid, ekuOidToCode, 1, KeyPurposeId.id_kp_serverAuth.toOID());
        registerTable(ekuCodeToOid, ekuOidToCode, 2, KeyPurposeId.id_kp_clientAuth.toOID());
        registerTable(ekuCodeToOid, ekuOidToCode, 3, KeyPurposeId.id_kp_codeSigning.toOID());
        registerTable(ekuCodeToOid, ekuOidToCode, 4, KeyPurposeId.id_kp_emailProtection.toOID());
        registerTable(ekuCodeToOid, ekuOidToCode, 8, KeyPurposeId.id_kp_timeStamping.toOID());
        registerTable(ekuCodeToOid, ekuOidToCode, 9, KeyPurposeId.id_kp_OCSPSigning.toOID());
        registerTable(ekuCodeToOid, ekuOidToCode, 10, KeyPurposeId.id_kp_pkinitClientAuth.toOID());
        registerTable(ekuCodeToOid, ekuOidToCode, 11, KeyPurposeId.id_kp_pkinitKdc.toOID());
        registerTable(ekuCodeToOid, ekuOidToCode, 12, KeyPurposeId.id_kp_secureShellClient.toOID());
        registerTable(ekuCodeToOid, ekuOidToCode, 13, KeyPurposeId.id_kp_secureShellServer.toOID());
        registerTable(ekuCodeToOid, ekuOidToCode, 14, KeyPurposeId.id_kp_bundleSecurity.toOID());
        registerTable(ekuCodeToOid, ekuOidToCode, 15, KeyPurposeId.id_kp_cmcCA.toOID());
        registerTable(ekuCodeToOid, ekuOidToCode, 16, KeyPurposeId.id_kp_cmcRA.toOID());
        registerTable(ekuCodeToOid, ekuOidToCode, 17, KeyPurposeId.id_kp_cmcArchive.toOID());
        registerTable(ekuCodeToOid, ekuOidToCode, 18, KeyPurposeId.id_kp_cmKGA.toOID());
        registerTable(ekuCodeToOid, ekuOidToCode, 20, "1.3.6.1.4.1.45605.1");

        // Figure 13: C509 Certificate Policies
        registerTable(policyCodeToOid, policyOidToCode, 0, "2.5.29.32.0");
        registerTable(policyCodeToOid, policyOidToCode, 1, "2.23.140.1.2.1");
        registerTable(policyCodeToOid, policyOidToCode, 2, "2.23.140.1.2.2");
        registerTable(policyCodeToOid, policyOidToCode, 3, "2.23.140.1.2.3");
        registerTable(policyCodeToOid, policyOidToCode, 4, "2.23.140.1.1");
        registerTable(policyCodeToOid, policyOidToCode, 7, "1.3.6.1.5.5.7.14.2");
        registerTable(policyCodeToOid, policyOidToCode, 8, "1.3.6.1.5.5.7.14.3");
        registerTable(policyCodeToOid, policyOidToCode, 24, "2.23.146.1.2.1.0");
        registerTable(policyCodeToOid, policyOidToCode, 25, "2.23.146.1.2.1.1");
        registerTable(policyCodeToOid, policyOidToCode, 26, "2.23.146.1.2.1.0.0.0.0.0");
        registerTable(policyCodeToOid, policyOidToCode, 27, "2.23.146.1.2.1.2");
        registerTable(policyCodeToOid, policyOidToCode, 28, "2.23.146.1.2.1.0.0.0");
        registerTable(policyCodeToOid, policyOidToCode, 29, "2.23.146.1.2.1.3");
        registerTable(policyCodeToOid, policyOidToCode, 30, "2.23.146.1.2.1.0.0.1.0");
        registerTable(policyCodeToOid, policyOidToCode, 31, "2.23.146.1.2.1.4");
        registerTable(policyCodeToOid, policyOidToCode, 32, "2.23.146.1.2.1.0.0.1.1");
        registerTable(policyCodeToOid, policyOidToCode, 33, "2.23.146.1.2.1.5");
        registerTable(policyCodeToOid, policyOidToCode, 34, "2.23.146.1.2.1.0.0.1.2");
        registerTable(policyCodeToOid, policyOidToCode, 35, "2.23.146.1.2.1.6");
        registerTable(policyCodeToOid, policyOidToCode, 36, "2.23.146.1.2.1.0.0.2.0");
        registerTable(policyCodeToOid, policyOidToCode, 37, "2.23.146.1.2.1.7");
        registerTable(policyCodeToOid, policyOidToCode, 38, "2.23.146.1.2.1.0.0.2.1");

        // Figure 15: C509 Information Accesses
        registerTable(accessCodeToOid, accessOidToCode, 1, X509ObjectIdentifiers.id_ad_ocsp);
        registerTable(accessCodeToOid, accessOidToCode, 2, X509ObjectIdentifiers.id_ad_caIssuers);
        registerTable(accessCodeToOid, accessOidToCode, 3, X509ObjectIdentifiers.id_ad.branch("3"));
        registerTable(accessCodeToOid, accessOidToCode, 5, X509ObjectIdentifiers.id_ad.branch("5"));
        registerTable(accessCodeToOid, accessOidToCode, 10, X509ObjectIdentifiers.id_ad.branch("10"));
        registerTable(accessCodeToOid, accessOidToCode, 11, X509ObjectIdentifiers.id_ad.branch("11"));
        registerTable(accessCodeToOid, accessOidToCode, 13, X509ObjectIdentifiers.id_ad.branch("13"));
    }

    /**
     * Encode a DER extension value in the specific CBOR encoding registered for the
     * extension, returning the encoded CBOR item, or null when the value cannot be
     * faithfully represented (the caller then uses the generic ~oid form).
     */
    static byte[] encodeValue(int extensionType, byte[] extnValue)
    {
        try
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            CBOREncoder out = new CBOREncoder(bOut);
            if (!encodeValue(extensionType, extnValue, out))
            {
                return null;
            }
            return bOut.toByteArray();
        }
        catch (IOException e)
        {
            return null;
        }
        catch (RuntimeException e)
        {
            // BC ASN.1 getInstance methods signal unexpected shapes with unchecked
            // exceptions; any such value simply has no specific encoding.
            return null;
        }
    }

    private static boolean encodeValue(int extensionType, byte[] extnValue, CBOREncoder out)
        throws IOException
    {
        switch (extensionType)
        {
        case C509ExtensionType.SUBJECT_KEY_IDENTIFIER:
        {
            ASN1OctetString keyId = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(extnValue));
            out.writeByteString(keyId.getOctets());
            return true;
        }
        case C509ExtensionType.KEY_USAGE:
        {
            ASN1BitString bits = ASN1BitString.getInstance(ASN1Primitive.fromByteArray(extnValue));
            out.writeUnsignedInteger(namedBitsToUint(bits));
            return true;
        }
        case C509ExtensionType.SUBJECT_ALT_NAME:
        case C509ExtensionType.ISSUER_ALT_NAME:
        {
            GeneralNames names = GeneralNames.getInstance(ASN1Primitive.fromByteArray(extnValue));
            GeneralName[] gns = names.getNames();
            if (gns.length == 1 && gns[0].getTagNo() == GeneralName.dNSName)
            {
                out.writeTextString(ASN1IA5String.getInstance(gns[0].getName()).getString());
                return true;
            }
            out.writeArrayHeader(2 * gns.length);
            for (int i = 0; i != gns.length; i++)
            {
                if (!encodeGeneralName(out, gns[i], false))
                {
                    return false;
                }
            }
            return true;
        }
        case C509ExtensionType.BASIC_CONSTRAINTS:
        {
            BasicConstraints bc = BasicConstraints.getInstance(ASN1Primitive.fromByteArray(extnValue));
            if (!bc.isCA())
            {
                // a pathLenConstraint on a non-CA certificate cannot be represented
                if (bc.getPathLenConstraint() != null)
                {
                    return false;
                }
                out.writeInteger(-2);
            }
            else if (bc.getPathLenConstraint() == null)
            {
                out.writeInteger(-1);
            }
            else
            {
                BigInteger pathLen = bc.getPathLenConstraint();
                if (pathLen.signum() < 0 || pathLen.bitLength() > 31)
                {
                    return false;
                }
                out.writeInteger(pathLen.intValue());
            }
            return true;
        }
        case C509ExtensionType.CRL_DISTRIBUTION_POINTS:
        case C509ExtensionType.FRESHEST_CRL:
            return encodeDistributionPoints(out, extnValue);
        case C509ExtensionType.CERTIFICATE_POLICIES:
            return encodeCertificatePolicies(out, extnValue);
        case C509ExtensionType.AUTHORITY_KEY_IDENTIFIER:
        {
            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(ASN1Primitive.fromByteArray(extnValue));
            byte[] keyId = aki.getKeyIdentifier();
            GeneralNames issuer = aki.getAuthorityCertIssuer();
            BigInteger serial = aki.getAuthorityCertSerialNumber();
            if (keyId != null && issuer == null && serial == null)
            {
                out.writeByteString(keyId);
                return true;
            }
            if (keyId == null || issuer == null || serial == null)
            {
                return false;
            }
            GeneralName[] gns = issuer.getNames();
            out.writeArrayHeader(3);
            out.writeByteString(keyId);
            out.writeArrayHeader(2 * gns.length);
            for (int i = 0; i != gns.length; i++)
            {
                if (!encodeGeneralName(out, gns[i], false))
                {
                    return false;
                }
            }
            if (serial.signum() <= 0)
            {
                return false;
            }
            out.writeByteString(BigIntegers.asUnsignedByteArray(serial));
            return true;
        }
        case C509ExtensionType.EXTENDED_KEY_USAGE:
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(extnValue));
            int count = seq.size();
            if (count == 0)
            {
                return false;
            }
            if (count > 1)
            {
                out.writeArrayHeader(count);
            }
            for (int i = 0; i != count; i++)
            {
                ASN1ObjectIdentifier purpose = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(i));
                Integer code = ekuOidToCode.get(purpose);
                if (code != null)
                {
                    out.writeInteger(code.intValue());
                }
                else
                {
                    out.writeByteString(C509Oids.toContents(purpose));
                }
            }
            return true;
        }
        case C509ExtensionType.AUTHORITY_INFO_ACCESS:
        case C509ExtensionType.SUBJECT_INFO_ACCESS:
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(extnValue));
            int count = seq.size();
            if (count == 0)
            {
                return false;
            }
            out.writeArrayHeader(2 * count);
            for (int i = 0; i != count; i++)
            {
                ASN1Sequence ad = ASN1Sequence.getInstance(seq.getObjectAt(i));
                if (ad.size() != 2)
                {
                    return false;
                }
                ASN1ObjectIdentifier method = ASN1ObjectIdentifier.getInstance(ad.getObjectAt(0));
                GeneralName location = GeneralName.getInstance(ad.getObjectAt(1));
                if (location.getTagNo() != GeneralName.uniformResourceIdentifier)
                {
                    return false;
                }
                Integer code = accessOidToCode.get(method);
                if (code != null)
                {
                    out.writeInteger(code.intValue());
                }
                else
                {
                    out.writeByteString(C509Oids.toContents(method));
                }
                out.writeTextString(ASN1IA5String.getInstance(location.getName()).getString());
            }
            return true;
        }
        case C509ExtensionType.SUBJECT_DIRECTORY_ATTRIBUTES:
            return encodeSubjectDirectoryAttributes(out, extnValue);
        case C509ExtensionType.NAME_CONSTRAINTS:
            return encodeNameConstraints(out, extnValue);
        case C509ExtensionType.POLICY_MAPPINGS:
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(extnValue));
            int count = seq.size();
            if (count == 0)
            {
                return false;
            }
            out.writeArrayHeader(2 * count);
            for (int i = 0; i != count; i++)
            {
                ASN1Sequence mapping = ASN1Sequence.getInstance(seq.getObjectAt(i));
                if (mapping.size() != 2)
                {
                    return false;
                }
                writePolicyId(out, ASN1ObjectIdentifier.getInstance(mapping.getObjectAt(0)));
                writePolicyId(out, ASN1ObjectIdentifier.getInstance(mapping.getObjectAt(1)));
            }
            return true;
        }
        case C509ExtensionType.POLICY_CONSTRAINTS:
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(extnValue));
            BigInteger require = null, inhibit = null;
            for (int i = 0; i != seq.size(); i++)
            {
                ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
                BigInteger value = ASN1Integer.getInstance(tagged, false).getValue();
                if (tagged.getTagNo() == 0 && require == null)
                {
                    require = value;
                }
                else if (tagged.getTagNo() == 1 && inhibit == null)
                {
                    inhibit = value;
                }
                else
                {
                    return false;
                }
            }
            writeUintOrNull(out, require);
            writeUintOrNull(out, inhibit);
            return true;
        }
        case C509ExtensionType.INHIBIT_ANY_POLICY:
        {
            BigInteger skip = ASN1Integer.getInstance(ASN1Primitive.fromByteArray(extnValue)).getValue();
            if (skip.signum() < 0 || skip.bitLength() > 63)
            {
                return false;
            }
            out.writeUnsignedInteger(skip.longValue());
            return true;
        }
        case C509ExtensionType.IP_ADDR_BLOCKS:
        case C509ExtensionType.IP_ADDR_BLOCKS_V2:
            return encodeIPAddrBlocks(out, extnValue);
        case C509ExtensionType.AS_IDENTIFIERS:
        case C509ExtensionType.AS_IDENTIFIERS_V2:
            return encodeASIdentifiers(out, extnValue);
        case C509ExtensionType.OCSP_NO_CHECK:
        {
            if (!(ASN1Primitive.fromByteArray(extnValue) instanceof ASN1Null))
            {
                return false;
            }
            out.writeNull();
            return true;
        }
        case C509ExtensionType.TLS_FEATURES:
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(extnValue));
            out.writeArrayHeader(seq.size());
            for (int i = 0; i != seq.size(); i++)
            {
                BigInteger feature = ASN1Integer.getInstance(seq.getObjectAt(i)).getValue();
                if (feature.signum() < 0 || feature.bitLength() > 63)
                {
                    return false;
                }
                out.writeUnsignedInteger(feature.longValue());
            }
            return true;
        }
        default:
            return false;
        }
    }

    /**
     * Decode the specific CBOR encoding of a registered extension value back to the
     * DER encoding of the extension value.
     */
    static byte[] decodeValue(int extensionType, CBORDecoder in)
        throws IOException
    {
        switch (extensionType)
        {
        case C509ExtensionType.SUBJECT_KEY_IDENTIFIER:
            return derEncode(new DEROctetString(in.readByteString()));
        case C509ExtensionType.KEY_USAGE:
            return derEncode(uintToNamedBits(in.readUnsignedInteger()));
        case C509ExtensionType.SUBJECT_ALT_NAME:
        case C509ExtensionType.ISSUER_ALT_NAME:
        {
            if (in.peekMajorType() == CBORType.TEXT_STRING)
            {
                return derEncode(new GeneralNames(new GeneralName(GeneralName.dNSName, in.readTextString())));
            }
            return derEncode(decodeGeneralNames(in, false));
        }
        case C509ExtensionType.BASIC_CONSTRAINTS:
        {
            int value = in.readInt();
            if (value == -2)
            {
                return derEncode(new BasicConstraints(false));
            }
            if (value == -1)
            {
                return derEncode(new BasicConstraints(true));
            }
            if (value < 0)
            {
                throw new IOException("malformed C509 BasicConstraints value: " + value);
            }
            return derEncode(new BasicConstraints(value));
        }
        case C509ExtensionType.CRL_DISTRIBUTION_POINTS:
        case C509ExtensionType.FRESHEST_CRL:
            return decodeDistributionPoints(in);
        case C509ExtensionType.CERTIFICATE_POLICIES:
            return decodeCertificatePolicies(in);
        case C509ExtensionType.AUTHORITY_KEY_IDENTIFIER:
        {
            if (in.peekMajorType() == CBORType.BYTE_STRING)
            {
                return derEncode(new AuthorityKeyIdentifier(in.readByteString()));
            }
            int count = in.readArrayHeader();
            if (count != 3)
            {
                throw new IOException("malformed C509 AuthorityKeyIdentifier");
            }
            byte[] keyId = in.readByteString();
            GeneralNames issuer = decodeGeneralNames(in, false);
            BigInteger serial = readBiguint(in);
            return derEncode(new AuthorityKeyIdentifier(keyId, issuer, serial));
        }
        case C509ExtensionType.EXTENDED_KEY_USAGE:
        {
            ASN1EncodableVector purposes = new ASN1EncodableVector();
            if (in.peekMajorType() == CBORType.ARRAY)
            {
                int count = in.readArrayHeader();
                if (count < 2)
                {
                    throw new IOException("C509 ExtKeyUsageSyntax array must hold at least 2 purposes");
                }
                for (int i = 0; i != count; i++)
                {
                    purposes.add(readEKUPurpose(in));
                }
            }
            else
            {
                purposes.add(readEKUPurpose(in));
            }
            return derEncode(new DERSequence(purposes));
        }
        case C509ExtensionType.AUTHORITY_INFO_ACCESS:
        case C509ExtensionType.SUBJECT_INFO_ACCESS:
        {
            int count = in.readArrayHeader();
            if (count < 2 || (count & 1) != 0)
            {
                throw new IOException("malformed C509 information access value");
            }
            ASN1EncodableVector descriptions = new ASN1EncodableVector();
            for (int i = 0; i != count; i += 2)
            {
                ASN1ObjectIdentifier method;
                if (in.peekMajorType() == CBORType.BYTE_STRING)
                {
                    method = C509Oids.fromContents(in.readByteString());
                }
                else
                {
                    int code = in.readInt();
                    method = accessCodeToOid.get(Integers.valueOf(code));
                    if (method == null)
                    {
                        throw new IOException("unknown C509 information access value: " + code);
                    }
                }
                GeneralName uri = new GeneralName(GeneralName.uniformResourceIdentifier, in.readTextString());
                descriptions.add(new DERSequence(new ASN1Encodable[]{ method, uri }));
            }
            return derEncode(new DERSequence(descriptions));
        }
        case C509ExtensionType.SUBJECT_DIRECTORY_ATTRIBUTES:
            return decodeSubjectDirectoryAttributes(in);
        case C509ExtensionType.NAME_CONSTRAINTS:
            return decodeNameConstraints(in);
        case C509ExtensionType.POLICY_MAPPINGS:
        {
            int count = in.readArrayHeader();
            if (count < 2 || (count & 1) != 0)
            {
                throw new IOException("malformed C509 PolicyMappings value");
            }
            ASN1EncodableVector mappings = new ASN1EncodableVector();
            for (int i = 0; i != count; i += 2)
            {
                ASN1ObjectIdentifier issuerPolicy = readPolicyId(in);
                ASN1ObjectIdentifier subjectPolicy = readPolicyId(in);
                mappings.add(new DERSequence(new ASN1Encodable[]{ issuerPolicy, subjectPolicy }));
            }
            return derEncode(new DERSequence(mappings));
        }
        case C509ExtensionType.POLICY_CONSTRAINTS:
        {
            int count = in.readArrayHeader();
            if (count != 2)
            {
                throw new IOException("malformed C509 PolicyConstraints value");
            }
            ASN1EncodableVector vec = new ASN1EncodableVector();
            if (in.nextIsNull())
            {
                in.readNull();
            }
            else
            {
                vec.add(new DERTaggedObject(false, 0, new ASN1Integer(in.readUnsignedInteger())));
            }
            if (in.nextIsNull())
            {
                in.readNull();
            }
            else
            {
                vec.add(new DERTaggedObject(false, 1, new ASN1Integer(in.readUnsignedInteger())));
            }
            return derEncode(new DERSequence(vec));
        }
        case C509ExtensionType.INHIBIT_ANY_POLICY:
            return derEncode(new ASN1Integer(in.readUnsignedInteger()));
        case C509ExtensionType.IP_ADDR_BLOCKS:
        case C509ExtensionType.IP_ADDR_BLOCKS_V2:
            return decodeIPAddrBlocks(in);
        case C509ExtensionType.AS_IDENTIFIERS:
        case C509ExtensionType.AS_IDENTIFIERS_V2:
            return decodeASIdentifiers(in);
        case C509ExtensionType.OCSP_NO_CHECK:
        {
            in.readNull();
            return derEncode(DERNull.INSTANCE);
        }
        case C509ExtensionType.TLS_FEATURES:
        {
            int count = in.readArrayHeader();
            ASN1EncodableVector features = new ASN1EncodableVector();
            for (int i = 0; i != count; i++)
            {
                features.add(new ASN1Integer(in.readUnsignedInteger()));
            }
            return derEncode(new DERSequence(features));
        }
        default:
            throw new IOException("unknown C509 extension value: " + extensionType);
        }
    }

    /*
     * KeyUsage / ReasonFlags: the BIT STRING is interpreted as an unsigned integer
     * where ASN.1 named bit i (counting from the most significant bit of the first
     * octet) maps to integer bit i (Sections 3.3 and 3.3.1: digitalSignature (0) ->
     * 2^0, keyAgreement (4) -> 2^4).
     */
    private static long namedBitsToUint(ASN1BitString bits)
        throws IOException
    {
        byte[] bytes = bits.getBytes();
        int padBits = bits.getPadBits();
        int bitCount = bytes.length * 8 - padBits;
        if (bitCount > 63)
        {
            throw new IOException("BIT STRING too long for C509 uint encoding");
        }
        long value = 0;
        for (int i = 0; i != bitCount; i++)
        {
            if ((bytes[i / 8] & (0x80 >>> (i % 8))) != 0)
            {
                value |= 1L << i;
            }
        }
        return value;
    }

    private static DERBitString uintToNamedBits(long value)
    {
        if (value == 0)
        {
            return new DERBitString(new byte[0], 0);
        }
        int highest = 63;
        while ((value & (1L << highest)) == 0)
        {
            highest--;
        }
        int byteCount = highest / 8 + 1;
        byte[] bytes = new byte[byteCount];
        for (int i = 0; i <= highest; i++)
        {
            if ((value & (1L << i)) != 0)
            {
                bytes[i / 8] |= (byte)(0x80 >>> (i % 8));
            }
        }
        int padBits = byteCount * 8 - (highest + 1);
        return new DERBitString(bytes, padBits);
    }

    /*
     * General names (Sections 3.3 and 8.13).
     */
    static boolean encodeGeneralName(CBOREncoder out, GeneralName name, boolean constraintContext)
        throws IOException
    {
        switch (name.getTagNo())
        {
        case GeneralName.otherName:
        {
            OtherName other = OtherName.getInstance(name.getName());
            ASN1ObjectIdentifier typeId = other.getTypeID();
            if (id_on_hardwareModuleName.equals(typeId))
            {
                ASN1Sequence hw = ASN1Sequence.getInstance(other.getValue());
                if (hw.size() != 2)
                {
                    return false;
                }
                out.writeInteger(GN_OTHER_NAME_HARDWARE_MODULE_NAME);
                out.writeArrayHeader(2);
                out.writeByteString(C509Oids.toContents(ASN1ObjectIdentifier.getInstance(hw.getObjectAt(0))));
                out.writeByteString(ASN1OctetString.getInstance(hw.getObjectAt(1)).getOctets());
                return true;
            }
            if (id_on_SmtpUTF8Mailbox.equals(typeId))
            {
                out.writeInteger(GN_OTHER_NAME_SMTP_UTF8_MAILBOX);
                out.writeTextString(ASN1UTF8String.getInstance(other.getValue()).getString());
                return true;
            }
            if (id_on_MACAddress.equals(typeId))
            {
                byte[] mac = ASN1OctetString.getInstance(other.getValue()).getOctets();
                if (mac.length != 6 && mac.length != 8)
                {
                    return false;
                }
                out.writeInteger(GN_OTHER_NAME_MAC_ADDRESS);
                out.writeByteString(mac);
                return true;
            }
            out.writeInteger(GN_OTHER_NAME);
            out.writeArrayHeader(2);
            out.writeByteString(C509Oids.toContents(typeId));
            out.writeByteString(other.getValue().toASN1Primitive().getEncoded(ASN1Encoding.DER));
            return true;
        }
        case GeneralName.rfc822Name:
            out.writeInteger(GN_RFC822_NAME);
            out.writeTextString(ASN1IA5String.getInstance(name.getName()).getString());
            return true;
        case GeneralName.dNSName:
            out.writeInteger(GN_DNS_NAME);
            out.writeTextString(ASN1IA5String.getInstance(name.getName()).getString());
            return true;
        case GeneralName.directoryName:
        {
            C509Name dirName;
            try
            {
                dirName = C509Name.fromX500Name(X500Name.getInstance(name.getName()));
            }
            catch (IllegalArgumentException e)
            {
                return false;
            }
            out.writeInteger(GN_DIRECTORY_NAME);
            dirName.encodeTo(out);
            return true;
        }
        case GeneralName.uniformResourceIdentifier:
            out.writeInteger(GN_URI);
            out.writeTextString(ASN1IA5String.getInstance(name.getName()).getString());
            return true;
        case GeneralName.iPAddress:
        {
            byte[] octets = ASN1OctetString.getInstance(name.getName()).getOctets();
            if (constraintContext)
            {
                byte[] prefixForm = maskToPrefixLength(octets);
                if (prefixForm == null)
                {
                    return false;
                }
                octets = prefixForm;
            }
            out.writeInteger(GN_IP_ADDRESS);
            out.writeByteString(octets);
            return true;
        }
        case GeneralName.registeredID:
            out.writeInteger(GN_REGISTERED_ID);
            out.writeByteString(C509Oids.toContents(ASN1ObjectIdentifier.getInstance(name.getName())));
            return true;
        default:
            // x400Address and ediPartyName have no C509 encoding
            return false;
        }
    }

    static GeneralName decodeGeneralName(CBORDecoder in, boolean constraintContext)
        throws IOException
    {
        int type = in.readInt();
        switch (type)
        {
        case GN_OTHER_NAME_MAC_ADDRESS:
        {
            byte[] mac = in.readByteString();
            if (mac.length != 6 && mac.length != 8)
            {
                throw new IOException("C509 MACAddress otherName must hold 6 or 8 octets");
            }
            return new GeneralName(GeneralName.otherName, new OtherName(id_on_MACAddress, new DEROctetString(mac)));
        }
        case GN_OTHER_NAME_SMTP_UTF8_MAILBOX:
            return new GeneralName(GeneralName.otherName,
                new OtherName(id_on_SmtpUTF8Mailbox, new DERUTF8String(in.readTextString())));
        case GN_OTHER_NAME_HARDWARE_MODULE_NAME:
        {
            int count = in.readArrayHeader();
            if (count != 2)
            {
                throw new IOException("malformed C509 hardwareModuleName otherName");
            }
            ASN1ObjectIdentifier hwType = C509Oids.fromContents(in.readByteString());
            byte[] hwSerialNum = in.readByteString();
            return new GeneralName(GeneralName.otherName, new OtherName(id_on_hardwareModuleName,
                new DERSequence(new ASN1Encodable[]{ hwType, new DEROctetString(hwSerialNum) })));
        }
        case GN_OTHER_NAME:
        {
            int count = in.readArrayHeader();
            if (count != 2)
            {
                throw new IOException("malformed C509 otherName");
            }
            ASN1ObjectIdentifier typeId = C509Oids.fromContents(in.readByteString());
            byte[] valueEncoding = in.readByteString();
            ASN1Primitive value;
            try
            {
                value = ASN1Primitive.fromByteArray(valueEncoding);
            }
            catch (RuntimeException e)
            {
                throw new IOException("malformed C509 otherName value");
            }
            return new GeneralName(GeneralName.otherName, new OtherName(typeId, value));
        }
        case GN_RFC822_NAME:
            return new GeneralName(GeneralName.rfc822Name, in.readTextString());
        case GN_DNS_NAME:
            return new GeneralName(GeneralName.dNSName, in.readTextString());
        case GN_DIRECTORY_NAME:
            return new GeneralName(GeneralName.directoryName, C509Name.parse(in).toX500Name());
        case GN_URI:
            return new GeneralName(GeneralName.uniformResourceIdentifier, in.readTextString());
        case GN_IP_ADDRESS:
        {
            byte[] octets = in.readByteString();
            if (constraintContext)
            {
                octets = prefixLengthToMask(octets);
            }
            else if (octets.length != 4 && octets.length != 16)
            {
                throw new IOException("C509 iPAddress must hold 4 or 16 octets");
            }
            return new GeneralName(GeneralName.iPAddress, new DEROctetString(octets));
        }
        case GN_REGISTERED_ID:
            return new GeneralName(GeneralName.registeredID, C509Oids.fromContents(in.readByteString()));
        default:
            throw new IOException("unknown C509 general name value: " + type);
        }
    }

    static GeneralNames decodeGeneralNames(CBORDecoder in, boolean constraintContext)
        throws IOException
    {
        int count = in.readArrayHeader();
        if (count == 0 || (count & 1) != 0)
        {
            throw new IOException("C509 GeneralNames must hold (type, value) pairs");
        }
        GeneralName[] names = new GeneralName[count / 2];
        for (int i = 0; i != names.length; i++)
        {
            names[i] = decodeGeneralName(in, constraintContext);
        }
        return new GeneralNames(names);
    }

    /**
     * Convert an RFC 5280 name constraint address (address followed by a mask of the
     * same length) to the RFC 9549 form used by C509 (address followed by a single
     * prefix length octet), returning null when the mask is not a contiguous prefix.
     */
    private static byte[] maskToPrefixLength(byte[] addressAndMask)
    {
        if (addressAndMask.length != 8 && addressAndMask.length != 32)
        {
            return null;
        }
        int addrLen = addressAndMask.length / 2;
        int prefixLength = -1;
        boolean seenZero = false;
        int bits = 0;
        for (int i = 0; i != addrLen; i++)
        {
            int m = addressAndMask[addrLen + i] & 0xFF;
            for (int b = 7; b >= 0; b--)
            {
                boolean one = (m & (1 << b)) != 0;
                if (one)
                {
                    if (seenZero)
                    {
                        return null;
                    }
                    bits++;
                }
                else
                {
                    seenZero = true;
                }
            }
        }
        prefixLength = bits;
        byte[] result = new byte[addrLen + 1];
        System.arraycopy(addressAndMask, 0, result, 0, addrLen);
        result[addrLen] = (byte)prefixLength;
        return result;
    }

    private static byte[] prefixLengthToMask(byte[] addressAndPrefix)
        throws IOException
    {
        if (addressAndPrefix.length != 5 && addressAndPrefix.length != 17)
        {
            throw new IOException("C509 name constraint iPAddress must hold 5 or 17 octets");
        }
        int addrLen = addressAndPrefix.length - 1;
        int prefixLength = addressAndPrefix[addrLen] & 0xFF;
        if (prefixLength > addrLen * 8)
        {
            throw new IOException("C509 name constraint prefix length out of range");
        }
        byte[] result = new byte[addrLen * 2];
        System.arraycopy(addressAndPrefix, 0, result, 0, addrLen);
        for (int i = 0; i != prefixLength; i++)
        {
            result[addrLen + i / 8] |= (byte)(0x80 >>> (i % 8));
        }
        return result;
    }

    /*
     * CRL Distribution Points / Freshest CRL.
     */
    private static boolean encodeDistributionPoints(CBOREncoder out, byte[] extnValue)
        throws IOException
    {
        CRLDistPoint crldp = CRLDistPoint.getInstance(ASN1Primitive.fromByteArray(extnValue));
        DistributionPoint[] points = crldp.getDistributionPoints();
        if (points.length == 0)
        {
            return false;
        }

        // gather (uris, reasons, crlIssuer) for each point, or fail
        String[][] uris = new String[points.length][];
        ASN1BitString[] reasons = new ASN1BitString[points.length];
        X500Name[] crlIssuers = new X500Name[points.length];
        for (int i = 0; i != points.length; i++)
        {
            DistributionPoint dp = points[i];
            DistributionPointName dpn = dp.getDistributionPoint();
            if (dpn == null || dpn.getType() != DistributionPointName.FULL_NAME)
            {
                return false;
            }
            GeneralName[] gns = GeneralNames.getInstance(dpn.getName()).getNames();
            if (gns.length == 0)
            {
                return false;
            }
            uris[i] = new String[gns.length];
            for (int j = 0; j != gns.length; j++)
            {
                if (gns[j].getTagNo() != GeneralName.uniformResourceIdentifier)
                {
                    return false;
                }
                uris[i][j] = ASN1IA5String.getInstance(gns[j].getName()).getString();
            }
            reasons[i] = dp.getReasons() == null ? null : ASN1BitString.getInstance(dp.getReasons());
            if (dp.getCRLIssuer() != null)
            {
                GeneralName[] issuerNames = dp.getCRLIssuer().getNames();
                if (issuerNames.length != 1 || issuerNames[0].getTagNo() != GeneralName.directoryName)
                {
                    return false;
                }
                crlIssuers[i] = X500Name.getInstance(issuerNames[0].getName());
            }
        }

        if (points.length == 1 && uris[0].length == 1 && reasons[0] == null && crlIssuers[0] == null)
        {
            out.writeTextString(uris[0][0]);
            return true;
        }

        out.writeArrayHeader(points.length);
        for (int i = 0; i != points.length; i++)
        {
            out.writeArrayHeader(3);
            if (uris[i].length == 1)
            {
                out.writeTextString(uris[i][0]);
            }
            else
            {
                out.writeArrayHeader(uris[i].length);
                for (int j = 0; j != uris[i].length; j++)
                {
                    out.writeTextString(uris[i][j]);
                }
            }
            if (reasons[i] == null)
            {
                out.writeNull();
            }
            else
            {
                out.writeUnsignedInteger(namedBitsToUint(reasons[i]));
            }
            if (crlIssuers[i] == null)
            {
                out.writeNull();
            }
            else
            {
                try
                {
                    C509Name.fromX500Name(crlIssuers[i]).encodeTo(out);
                }
                catch (IllegalArgumentException e)
                {
                    return false;
                }
            }
        }
        return true;
    }

    private static byte[] decodeDistributionPoints(CBORDecoder in)
        throws IOException
    {
        if (in.peekMajorType() == CBORType.TEXT_STRING)
        {
            return derEncode(new CRLDistPoint(new DistributionPoint[]
                { buildDistributionPoint(new String[]{ in.readTextString() }, null, null) }));
        }

        int count = in.readArrayHeader();
        if (count == 0)
        {
            throw new IOException("C509 CRLDistributionPoints cannot be empty");
        }
        DistributionPoint[] points = new DistributionPoint[count];
        for (int i = 0; i != count; i++)
        {
            int fields = in.readArrayHeader();
            if (fields != 3)
            {
                throw new IOException("malformed C509 DistributionPointName");
            }
            String[] uris;
            if (in.peekMajorType() == CBORType.ARRAY)
            {
                int uriCount = in.readArrayHeader();
                if (uriCount < 2)
                {
                    throw new IOException("C509 DistributionPointName fullName array must hold at least 2 names");
                }
                uris = new String[uriCount];
                for (int j = 0; j != uriCount; j++)
                {
                    uris[j] = in.readTextString();
                }
            }
            else
            {
                uris = new String[]{ in.readTextString() };
            }
            Long reasons = null;
            if (in.nextIsNull())
            {
                in.readNull();
            }
            else
            {
                reasons = Longs.valueOf(in.readUnsignedInteger());
            }
            X500Name crlIssuer = null;
            if (in.nextIsNull())
            {
                in.readNull();
            }
            else
            {
                crlIssuer = C509Name.parse(in).toX500Name();
            }
            points[i] = buildDistributionPoint(uris, reasons, crlIssuer);
        }
        return derEncode(new CRLDistPoint(points));
    }

    private static DistributionPoint buildDistributionPoint(String[] uris, Long reasons, X500Name crlIssuer)
    {
        GeneralName[] gns = new GeneralName[uris.length];
        for (int i = 0; i != uris.length; i++)
        {
            gns[i] = new GeneralName(GeneralName.uniformResourceIdentifier, uris[i]);
        }
        DistributionPointName dpn = new DistributionPointName(new GeneralNames(gns));
        ReasonFlags reasonFlags = null;
        if (reasons != null)
        {
            reasonFlags = new ReasonFlags(uintToNamedBits(reasons.longValue()));
        }
        GeneralNames issuerNames = null;
        if (crlIssuer != null)
        {
            issuerNames = new GeneralNames(new GeneralName(crlIssuer));
        }
        return new DistributionPoint(dpn, reasonFlags, issuerNames);
    }

    /*
     * Certificate Policies.
     */
    private static void writePolicyId(CBOREncoder out, ASN1ObjectIdentifier policy)
        throws IOException
    {
        Integer code = policyOidToCode.get(policy);
        if (code != null)
        {
            out.writeInteger(code.intValue());
        }
        else
        {
            out.writeByteString(C509Oids.toContents(policy));
        }
    }

    private static ASN1ObjectIdentifier readPolicyId(CBORDecoder in)
        throws IOException
    {
        if (in.peekMajorType() == CBORType.BYTE_STRING)
        {
            return C509Oids.fromContents(in.readByteString());
        }
        int code = in.readInt();
        ASN1ObjectIdentifier policy = policyCodeToOid.get(Integers.valueOf(code));
        if (policy == null)
        {
            throw new IOException("unknown C509 certificate policy value: " + code);
        }
        return policy;
    }

    private static boolean encodeCertificatePolicies(CBOREncoder out, byte[] extnValue)
        throws IOException
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(extnValue));
        int count = seq.size();
        if (count == 0)
        {
            return false;
        }
        // first pass: check every policy and qualifier is representable
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder tmp = new CBOREncoder(bOut);
        for (int i = 0; i != count; i++)
        {
            PolicyInformation policy = PolicyInformation.getInstance(seq.getObjectAt(i));
            writePolicyId(tmp, policy.getPolicyIdentifier());
            ASN1Sequence qualifiers = policy.getPolicyQualifiers();
            int qualifierCount = qualifiers == null ? 0 : qualifiers.size();
            tmp.writeArrayHeader(2 * qualifierCount);
            for (int j = 0; j != qualifierCount; j++)
            {
                PolicyQualifierInfo qualifier = PolicyQualifierInfo.getInstance(qualifiers.getObjectAt(j));
                ASN1ObjectIdentifier qualifierId = qualifier.getPolicyQualifierId();
                if (id_qt_cps.equals(qualifierId))
                {
                    tmp.writeInteger(1);
                    tmp.writeTextString(ASN1IA5String.getInstance(qualifier.getQualifier()).getString());
                }
                else if (id_qt_unotice.equals(qualifierId))
                {
                    UserNotice notice = UserNotice.getInstance(qualifier.getQualifier());
                    if (notice.getNoticeRef() != null || notice.getExplicitText() == null)
                    {
                        return false;
                    }
                    DisplayText text = notice.getExplicitText();
                    if (!(text.toASN1Primitive() instanceof ASN1UTF8String))
                    {
                        return false;
                    }
                    tmp.writeInteger(2);
                    tmp.writeTextString(text.getString());
                }
                else
                {
                    // the qualifier value's type could not be recovered on decode
                    return false;
                }
            }
        }
        out.writeArrayHeader(2 * count);
        out.writeEncoded(bOut.toByteArray());
        return true;
    }

    private static byte[] decodeCertificatePolicies(CBORDecoder in)
        throws IOException
    {
        int count = in.readArrayHeader();
        if (count == 0 || (count & 1) != 0)
        {
            throw new IOException("malformed C509 CertificatePolicies value");
        }
        ASN1EncodableVector policies = new ASN1EncodableVector();
        for (int i = 0; i != count; i += 2)
        {
            ASN1ObjectIdentifier policyId = readPolicyId(in);
            int qualifierCount = in.readArrayHeader();
            if ((qualifierCount & 1) != 0)
            {
                throw new IOException("malformed C509 PolicyQualifierInfo value");
            }
            if (qualifierCount == 0)
            {
                policies.add(new PolicyInformation(policyId));
                continue;
            }
            ASN1EncodableVector qualifiers = new ASN1EncodableVector();
            for (int j = 0; j != qualifierCount; j += 2)
            {
                if (in.peekMajorType() == CBORType.BYTE_STRING)
                {
                    throw new IOException("C509 policy qualifier with OID identifier cannot be reconstructed");
                }
                int qualifierId = in.readInt();
                String text = in.readTextString();
                if (qualifierId == 1)
                {
                    qualifiers.add(new PolicyQualifierInfo(text));
                }
                else if (qualifierId == 2)
                {
                    qualifiers.add(new PolicyQualifierInfo(id_qt_unotice,
                        new UserNotice(null, new DisplayText(DisplayText.CONTENT_TYPE_UTF8STRING, text))));
                }
                else
                {
                    throw new IOException("unknown C509 policy qualifier value: " + qualifierId);
                }
            }
            policies.add(new PolicyInformation(policyId, new DERSequence(qualifiers)));
        }
        return derEncode(new DERSequence(policies));
    }

    /*
     * Subject Directory Attributes.
     */
    private static boolean encodeSubjectDirectoryAttributes(CBOREncoder out, byte[] extnValue)
        throws IOException
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(extnValue));
        int count = seq.size();
        if (count == 0)
        {
            return false;
        }
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder tmp = new CBOREncoder(bOut);
        for (int i = 0; i != count; i++)
        {
            ASN1Sequence attribute = ASN1Sequence.getInstance(seq.getObjectAt(i));
            if (attribute.size() != 2)
            {
                return false;
            }
            ASN1ObjectIdentifier type = ASN1ObjectIdentifier.getInstance(attribute.getObjectAt(0));
            ASN1Set values = ASN1Set.getInstance(attribute.getObjectAt(1));
            if (values.size() == 0)
            {
                return false;
            }
            Integer code = C509AttributeType.getValue(type);
            int stringKind = -1; // 0 utf8, 1 printable, 2 ia5
            if (code != null)
            {
                stringKind = commonStringKind(values);
                int c = code.intValue();
                if (C509AttributeType.isAlwaysIA5String(c))
                {
                    if (stringKind != 2)
                    {
                        stringKind = -1;
                    }
                }
                else if (stringKind == 2 || (stringKind == 1 && c == 0))
                {
                    stringKind = -1;
                }
            }
            if (code != null && stringKind >= 0)
            {
                tmp.writeInteger(stringKind == 1 ? -code.intValue() : code.intValue());
                tmp.writeArrayHeader(values.size());
                for (int j = 0; j != values.size(); j++)
                {
                    C509Name.writeSpecialText(tmp, getString(values.getObjectAt(j)));
                }
            }
            else
            {
                tmp.writeByteString(C509Oids.toContents(type));
                tmp.writeArrayHeader(values.size());
                for (int j = 0; j != values.size(); j++)
                {
                    tmp.writeByteString(values.getObjectAt(j).toASN1Primitive().getEncoded(ASN1Encoding.DER));
                }
            }
        }
        out.writeArrayHeader(2 * count);
        out.writeEncoded(bOut.toByteArray());
        return true;
    }

    /**
     * Return 0 when all values are utf8Strings, 1 when all are printableStrings, 2
     * when all are IA5Strings, and -1 for anything else.
     */
    private static int commonStringKind(ASN1Set values)
    {
        int kind = -1;
        for (int i = 0; i != values.size(); i++)
        {
            ASN1Encodable value = values.getObjectAt(i);
            int thisKind;
            if (value instanceof ASN1UTF8String)
            {
                thisKind = 0;
            }
            else if (value instanceof ASN1PrintableString)
            {
                thisKind = 1;
            }
            else if (value instanceof ASN1IA5String)
            {
                thisKind = 2;
            }
            else
            {
                return -1;
            }
            if (kind == -1)
            {
                kind = thisKind;
            }
            else if (kind != thisKind)
            {
                return -1;
            }
        }
        return kind;
    }

    private static String getString(ASN1Encodable value)
    {
        if (value instanceof ASN1UTF8String)
        {
            return ((ASN1UTF8String)value).getString();
        }
        if (value instanceof ASN1PrintableString)
        {
            return ((ASN1PrintableString)value).getString();
        }
        return ((ASN1IA5String)value).getString();
    }

    private static byte[] decodeSubjectDirectoryAttributes(CBORDecoder in)
        throws IOException
    {
        int count = in.readArrayHeader();
        if (count == 0 || (count & 1) != 0)
        {
            throw new IOException("malformed C509 SubjectDirectoryAttributes value");
        }
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        for (int i = 0; i != count; i += 2)
        {
            if (in.peekMajorType() == CBORType.BYTE_STRING)
            {
                ASN1ObjectIdentifier type = C509Oids.fromContents(in.readByteString());
                int valueCount = in.readArrayHeader();
                if (valueCount == 0)
                {
                    throw new IOException("C509 attribute values cannot be empty");
                }
                ASN1EncodableVector values = new ASN1EncodableVector();
                for (int j = 0; j != valueCount; j++)
                {
                    byte[] valueEncoding = in.readByteString();
                    try
                    {
                        values.add(ASN1Primitive.fromByteArray(valueEncoding));
                    }
                    catch (RuntimeException e)
                    {
                        throw new IOException("malformed C509 attribute value");
                    }
                }
                attributes.add(new DERSequence(new ASN1Encodable[]{ type, new DERSet(values) }));
            }
            else
            {
                int typeValue = in.readInt();
                int code = typeValue < 0 ? -typeValue : typeValue;
                ASN1ObjectIdentifier type = C509AttributeType.getOID(code);
                if (type == null)
                {
                    throw new IOException("unknown C509 RDN attribute value: " + code);
                }
                if (typeValue < 0 && C509AttributeType.isAlwaysIA5String(code))
                {
                    throw new IOException("C509 RDN attribute " + code + " is always IA5String and must be non-negative");
                }
                int valueCount = in.readArrayHeader();
                if (valueCount == 0)
                {
                    throw new IOException("C509 attribute values cannot be empty");
                }
                ASN1EncodableVector values = new ASN1EncodableVector();
                for (int j = 0; j != valueCount; j++)
                {
                    String text = C509Name.readSpecialText(in);
                    if (C509AttributeType.isAlwaysIA5String(code))
                    {
                        values.add(new DERIA5String(text));
                    }
                    else if (typeValue < 0)
                    {
                        values.add(new DERPrintableString(text));
                    }
                    else
                    {
                        values.add(new DERUTF8String(text));
                    }
                }
                attributes.add(new DERSequence(new ASN1Encodable[]{ type, new DERSet(values) }));
            }
        }
        return derEncode(new DERSequence(attributes));
    }

    /*
     * Name Constraints.
     */
    private static boolean encodeNameConstraints(CBOREncoder out, byte[] extnValue)
        throws IOException
    {
        NameConstraints nc = NameConstraints.getInstance(ASN1Primitive.fromByteArray(extnValue));
        GeneralSubtree[] permitted = nc.getPermittedSubtrees();
        GeneralSubtree[] excluded = nc.getExcludedSubtrees();
        if (permitted == null && excluded == null)
        {
            return false;
        }
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder tmp = new CBOREncoder(bOut);
        if (!encodeGeneralSubtrees(tmp, permitted))
        {
            return false;
        }
        if (!encodeGeneralSubtrees(tmp, excluded))
        {
            return false;
        }
        out.writeArrayHeader(2);
        out.writeEncoded(bOut.toByteArray());
        return true;
    }

    private static boolean encodeGeneralSubtrees(CBOREncoder out, GeneralSubtree[] subtrees)
        throws IOException
    {
        if (subtrees == null)
        {
            out.writeNull();
            return true;
        }
        if (subtrees.length == 0)
        {
            return false;
        }
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder tmp = new CBOREncoder(bOut);
        for (int i = 0; i != subtrees.length; i++)
        {
            // the minimum and maximum fields are not used and are omitted (Section 3.3)
            if (subtrees[i].getMinimum().signum() != 0 || subtrees[i].getMaximum() != null)
            {
                return false;
            }
            if (!encodeGeneralName(tmp, subtrees[i].getBase(), true))
            {
                return false;
            }
        }
        out.writeArrayHeader(2 * subtrees.length);
        out.writeEncoded(bOut.toByteArray());
        return true;
    }

    private static byte[] decodeNameConstraints(CBORDecoder in)
        throws IOException
    {
        int count = in.readArrayHeader();
        if (count != 2)
        {
            throw new IOException("malformed C509 NameConstraints value");
        }
        GeneralSubtree[] permitted = decodeGeneralSubtrees(in);
        GeneralSubtree[] excluded = decodeGeneralSubtrees(in);
        if (permitted == null && excluded == null)
        {
            throw new IOException("C509 NameConstraints must hold at least one subtree list");
        }
        return derEncode(new NameConstraints(permitted, excluded));
    }

    private static GeneralSubtree[] decodeGeneralSubtrees(CBORDecoder in)
        throws IOException
    {
        if (in.nextIsNull())
        {
            in.readNull();
            return null;
        }
        int count = in.readArrayHeader();
        if (count == 0 || (count & 1) != 0)
        {
            throw new IOException("malformed C509 GeneralSubtrees value");
        }
        GeneralSubtree[] subtrees = new GeneralSubtree[count / 2];
        for (int i = 0; i != subtrees.length; i++)
        {
            subtrees[i] = new GeneralSubtree(decodeGeneralName(in, true));
        }
        return subtrees;
    }

    /*
     * RFC 3779 IPAddrBlocks. The ASN.1 BIT STRING of each IPAddress is treated as the
     * byte sequence unusedBits || value; for the int representation the values are
     * (unusedBits + 1) || value read as a big-endian integer (the +1 guarantees a
     * non-zero leading byte so the length round-trips), delta-coded against the
     * previous address; the byte representation carries unusedBits || value verbatim.
     */
    private static boolean encodeIPAddrBlocks(CBOREncoder out, byte[] extnValue)
        throws IOException
    {
        ASN1Sequence blocks = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(extnValue));
        int familyCount = blocks.size();
        if (familyCount == 0)
        {
            return false;
        }
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder tmp = new CBOREncoder(bOut);
        for (int i = 0; i != familyCount; i++)
        {
            ASN1Sequence family = ASN1Sequence.getInstance(blocks.getObjectAt(i));
            if (family.size() != 2)
            {
                return false;
            }
            byte[] addressFamily = ASN1OctetString.getInstance(family.getObjectAt(0)).getOctets();
            if (addressFamily.length != 2 && addressFamily.length != 3)
            {
                return false;
            }
            tmp.writeUnsignedInteger(((addressFamily[0] & 0xFF) << 8) | (addressFamily[1] & 0xFF));
            if (addressFamily.length == 3)
            {
                tmp.writeUnsignedInteger(addressFamily[2] & 0xFF);
            }
            else
            {
                tmp.writeNull();
            }

            ASN1Encodable choice = family.getObjectAt(1);
            if (choice instanceof ASN1Null)
            {
                tmp.writeNull();
                continue;
            }
            ASN1Sequence entries = ASN1Sequence.getInstance(choice);

            // collect the byte sequences
            Vector<byte[][]> collected = new Vector<byte[][]>();
            boolean intForm = true;
            for (int j = 0; j != entries.size(); j++)
            {
                ASN1Encodable entry = entries.getObjectAt(j);
                byte[][] seqs;
                if (entry instanceof ASN1BitString)
                {
                    seqs = new byte[][]{ bitStringByteSequence(ASN1BitString.getInstance(entry)) };
                }
                else
                {
                    ASN1Sequence range = ASN1Sequence.getInstance(entry);
                    if (range.size() != 2)
                    {
                        return false;
                    }
                    seqs = new byte[][]
                    {
                        bitStringByteSequence(ASN1BitString.getInstance(range.getObjectAt(0))),
                        bitStringByteSequence(ASN1BitString.getInstance(range.getObjectAt(1)))
                    };
                }
                for (int k = 0; k != seqs.length; k++)
                {
                    if (seqs[k].length > 8)
                    {
                        intForm = false;
                    }
                }
                collected.addElement(seqs);
            }

            tmp.writeArrayHeader(collected.size());
            BigInteger previous = null;
            for (int j = 0; j != collected.size(); j++)
            {
                byte[][] seqs = collected.elementAt(j);
                if (intForm)
                {
                    BigInteger[] encodedValues = new BigInteger[seqs.length];
                    for (int k = 0; k != seqs.length; k++)
                    {
                        byte[] seq = seqs[k];
                        byte[] shifted = new byte[seq.length];
                        System.arraycopy(seq, 1, shifted, 1, seq.length - 1);
                        shifted[0] = (byte)(seq[0] + 1);
                        BigInteger value = new BigInteger(1, shifted);
                        encodedValues[k] = previous == null ? value : value.subtract(previous);
                        previous = value;
                    }
                    if (seqs.length == 1)
                    {
                        tmp.writeInteger(encodedValues[0]);
                    }
                    else
                    {
                        tmp.writeArrayHeader(2);
                        tmp.writeInteger(encodedValues[0]);
                        tmp.writeInteger(encodedValues[1]);
                    }
                }
                else
                {
                    if (seqs.length == 1)
                    {
                        tmp.writeByteString(seqs[0]);
                    }
                    else
                    {
                        tmp.writeArrayHeader(2);
                        tmp.writeByteString(seqs[0]);
                        tmp.writeByteString(seqs[1]);
                    }
                }
            }
        }
        out.writeArrayHeader(countIPFamilyItems(blocks));
        out.writeEncoded(bOut.toByteArray());
        return true;
    }

    private static int countIPFamilyItems(ASN1Sequence blocks)
    {
        return 3 * blocks.size();
    }

    private static byte[] bitStringByteSequence(ASN1BitString bits)
    {
        byte[] value = bits.getBytes();
        byte[] seq = new byte[value.length + 1];
        seq[0] = (byte)bits.getPadBits();
        System.arraycopy(value, 0, seq, 1, value.length);
        return seq;
    }

    private static DERBitString byteSequenceToBitString(byte[] seq)
        throws IOException
    {
        if (seq.length < 1)
        {
            throw new IOException("malformed C509 IPAddress byte sequence");
        }
        int unusedBits = seq[0] & 0xFF;
        if (unusedBits > 7 || (seq.length == 1 && unusedBits != 0))
        {
            throw new IOException("malformed C509 IPAddress byte sequence");
        }
        byte[] value = new byte[seq.length - 1];
        System.arraycopy(seq, 1, value, 0, value.length);
        return new DERBitString(value, unusedBits);
    }

    private static byte[] decodeIPAddrBlocks(CBORDecoder in)
        throws IOException
    {
        int itemCount = in.readArrayHeader();
        if (itemCount == 0 || itemCount % 3 != 0)
        {
            throw new IOException("malformed C509 IPAddrBlocks value");
        }
        ASN1EncodableVector families = new ASN1EncodableVector();
        for (int i = 0; i != itemCount; i += 3)
        {
            long afi = in.readUnsignedInteger();
            if (afi > 0xFFFF)
            {
                throw new IOException("C509 AFI out of range");
            }
            int safi = -1;
            if (in.nextIsNull())
            {
                in.readNull();
            }
            else
            {
                long safiValue = in.readUnsignedInteger();
                if (safiValue > 0xFF)
                {
                    throw new IOException("C509 SAFI out of range");
                }
                safi = (int)safiValue;
            }
            byte[] addressFamily = new byte[safi < 0 ? 2 : 3];
            addressFamily[0] = (byte)(afi >>> 8);
            addressFamily[1] = (byte)afi;
            if (safi >= 0)
            {
                addressFamily[2] = (byte)safi;
            }

            ASN1Encodable choice;
            if (in.nextIsNull())
            {
                in.readNull();
                choice = DERNull.INSTANCE;
            }
            else
            {
                int entryCount = in.readArrayHeader();
                if (entryCount == 0)
                {
                    throw new IOException("C509 IPAddressChoice cannot be empty");
                }
                ASN1EncodableVector entries = new ASN1EncodableVector();
                BigInteger previous = null;
                for (int j = 0; j != entryCount; j++)
                {
                    int major = in.peekMajorType();
                    if (major == CBORType.BYTE_STRING)
                    {
                        entries.add(byteSequenceToBitString(in.readByteString()));
                    }
                    else if (major == CBORType.ARRAY)
                    {
                        int pair = in.readArrayHeader();
                        if (pair != 2)
                        {
                            throw new IOException("malformed C509 address range");
                        }
                        if (in.peekMajorType() == CBORType.BYTE_STRING)
                        {
                            DERBitString min = byteSequenceToBitString(in.readByteString());
                            DERBitString max = byteSequenceToBitString(in.readByteString());
                            entries.add(new DERSequence(new ASN1Encodable[]{ min, max }));
                        }
                        else
                        {
                            BigInteger min = applyDelta(in.readBigInteger(), previous);
                            previous = min;
                            BigInteger max = applyDelta(in.readBigInteger(), previous);
                            previous = max;
                            entries.add(new DERSequence(new ASN1Encodable[]
                                { intToBitString(min), intToBitString(max) }));
                        }
                    }
                    else
                    {
                        BigInteger value = applyDelta(in.readBigInteger(), previous);
                        previous = value;
                        entries.add(intToBitString(value));
                    }
                }
                choice = new DERSequence(entries);
            }
            families.add(new DERSequence(new ASN1Encodable[]{ new DEROctetString(addressFamily), choice }));
        }
        return derEncode(new DERSequence(families));
    }

    private static BigInteger applyDelta(BigInteger delta, BigInteger previous)
        throws IOException
    {
        BigInteger value = previous == null ? delta : previous.add(delta);
        if (value.signum() <= 0)
        {
            throw new IOException("malformed C509 delta-coded address value");
        }
        return value;
    }

    private static DERBitString intToBitString(BigInteger value)
        throws IOException
    {
        byte[] seq = BigIntegers.asUnsignedByteArray(value);
        if (seq.length < 1 || seq.length > 8)
        {
            throw new IOException("C509 int-coded IPAddress out of range");
        }
        int unusedBits = (seq[0] & 0xFF) - 1;
        if (unusedBits > 7 || (seq.length == 1 && unusedBits != 0))
        {
            throw new IOException("malformed C509 int-coded IPAddress");
        }
        byte[] bitValue = new byte[seq.length - 1];
        System.arraycopy(seq, 1, bitValue, 0, bitValue.length);
        return new DERBitString(bitValue, unusedBits);
    }

    /*
     * RFC 3779 ASIdentifiers. Only the asnum choice is supported; each ASId is
     * delta-coded against the previous one.
     */
    private static boolean encodeASIdentifiers(CBOREncoder out, byte[] extnValue)
        throws IOException
    {
        ASN1Sequence asIds = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(extnValue));
        if (asIds.size() != 1)
        {
            // rdi present (or nothing at all) cannot be represented
            return false;
        }
        ASN1TaggedObject asnum = ASN1TaggedObject.getInstance(asIds.getObjectAt(0));
        if (asnum.getTagNo() != 0)
        {
            return false;
        }
        ASN1Encodable choice = asnum.getExplicitBaseObject();
        if (choice instanceof ASN1Null)
        {
            out.writeNull();
            return true;
        }
        ASN1Sequence entries = ASN1Sequence.getInstance(choice);
        if (entries.size() == 0)
        {
            return false;
        }
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder tmp = new CBOREncoder(bOut);
        BigInteger previous = null;
        for (int i = 0; i != entries.size(); i++)
        {
            ASN1Encodable entry = entries.getObjectAt(i);
            if (entry instanceof ASN1Integer)
            {
                BigInteger id = ((ASN1Integer)entry).getValue();
                if (id.signum() < 0 || id.bitLength() > 64)
                {
                    return false;
                }
                tmp.writeInteger(previous == null ? id : id.subtract(previous));
                previous = id;
            }
            else
            {
                ASN1Sequence range = ASN1Sequence.getInstance(entry);
                if (range.size() != 2)
                {
                    return false;
                }
                BigInteger min = ASN1Integer.getInstance(range.getObjectAt(0)).getValue();
                BigInteger max = ASN1Integer.getInstance(range.getObjectAt(1)).getValue();
                if (min.signum() < 0 || min.bitLength() > 64 || max.signum() < 0 || max.bitLength() > 64)
                {
                    return false;
                }
                tmp.writeArrayHeader(2);
                tmp.writeInteger(previous == null ? min : min.subtract(previous));
                tmp.writeInteger(max.subtract(min));
                previous = max;
            }
        }
        out.writeArrayHeader(entries.size());
        out.writeEncoded(bOut.toByteArray());
        return true;
    }

    private static byte[] decodeASIdentifiers(CBORDecoder in)
        throws IOException
    {
        ASN1Encodable choice;
        if (in.nextIsNull())
        {
            in.readNull();
            choice = DERNull.INSTANCE;
        }
        else
        {
            int count = in.readArrayHeader();
            if (count == 0)
            {
                throw new IOException("C509 ASIdentifiers cannot be empty");
            }
            ASN1EncodableVector entries = new ASN1EncodableVector();
            BigInteger previous = null;
            for (int i = 0; i != count; i++)
            {
                if (in.peekMajorType() == CBORType.ARRAY)
                {
                    int pair = in.readArrayHeader();
                    if (pair != 2)
                    {
                        throw new IOException("malformed C509 ASRange");
                    }
                    BigInteger min = applyASDelta(in.readBigInteger(), previous);
                    BigInteger max = applyASDelta(in.readBigInteger(), min);
                    previous = max;
                    entries.add(new DERSequence(new ASN1Encodable[]
                        { new ASN1Integer(min), new ASN1Integer(max) }));
                }
                else
                {
                    BigInteger id = applyASDelta(in.readBigInteger(), previous);
                    previous = id;
                    entries.add(new ASN1Integer(id));
                }
            }
            choice = new DERSequence(entries);
        }
        return derEncode(new DERSequence(new DERTaggedObject(true, 0, choice)));
    }

    private static BigInteger applyASDelta(BigInteger delta, BigInteger previous)
        throws IOException
    {
        BigInteger value = previous == null ? delta : previous.add(delta);
        if (value.signum() < 0 || value.bitLength() > 64)
        {
            throw new IOException("malformed C509 delta-coded AS identifier");
        }
        return value;
    }

    private static ASN1Encodable readEKUPurpose(CBORDecoder in)
        throws IOException
    {
        if (in.peekMajorType() == CBORType.BYTE_STRING)
        {
            return C509Oids.fromContents(in.readByteString());
        }
        int code = in.readInt();
        ASN1ObjectIdentifier purpose = ekuCodeToOid.get(Integers.valueOf(code));
        if (purpose == null)
        {
            throw new IOException("unknown C509 extended key usage value: " + code);
        }
        return purpose;
    }

    private static void writeUintOrNull(CBOREncoder out, BigInteger value)
        throws IOException
    {
        if (value == null)
        {
            out.writeNull();
        }
        else
        {
            if (value.signum() < 0 || value.bitLength() > 63)
            {
                throw new IOException("value out of range");
            }
            out.writeUnsignedInteger(value.longValue());
        }
    }

    static BigInteger readBiguint(CBORDecoder in)
        throws IOException
    {
        byte[] magnitude = in.readByteString();
        if (magnitude.length > 0 && magnitude[0] == 0)
        {
            throw new IOException("C509 biguint with leading zero octet");
        }
        return new BigInteger(1, magnitude);
    }

    static byte[] derEncode(ASN1Encodable value)
        throws IOException
    {
        return value.toASN1Primitive().getEncoded(ASN1Encoding.DER);
    }

    private C509ExtensionValueCodec()
    {
    }
}
