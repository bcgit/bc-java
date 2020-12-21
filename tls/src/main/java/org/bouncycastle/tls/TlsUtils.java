package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Shorts;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

/**
 * Some helper functions for the TLS API.
 */
public class TlsUtils
{
    private static byte[] DOWNGRADE_TLS11 = Hex.decodeStrict("444F574E47524400");
    private static byte[] DOWNGRADE_TLS12 = Hex.decodeStrict("444F574E47524401");

    // Map OID strings to HashAlgorithm values
    private static final Hashtable CERT_SIG_ALG_OIDS = createCertSigAlgOIDs();
    private static final Vector DEFAULT_SUPPORTED_SIG_ALGS = createDefaultSupportedSigAlgs();

    private static void addCertSigAlgOID(Hashtable h, ASN1ObjectIdentifier oid, short hashAlgorithm, short signatureAlgorithm)
    {
        h.put(oid.getId(), SignatureAndHashAlgorithm.getInstance(hashAlgorithm, signatureAlgorithm));
    }

    private static Hashtable createCertSigAlgOIDs()
    {
        Hashtable h = new Hashtable();

        addCertSigAlgOID(h, NISTObjectIdentifiers.dsa_with_sha224, HashAlgorithm.sha224, SignatureAlgorithm.dsa);
        addCertSigAlgOID(h, NISTObjectIdentifiers.dsa_with_sha256, HashAlgorithm.sha256, SignatureAlgorithm.dsa);
        addCertSigAlgOID(h, NISTObjectIdentifiers.dsa_with_sha384, HashAlgorithm.sha384, SignatureAlgorithm.dsa);
        addCertSigAlgOID(h, NISTObjectIdentifiers.dsa_with_sha512, HashAlgorithm.sha512, SignatureAlgorithm.dsa);

        addCertSigAlgOID(h, OIWObjectIdentifiers.dsaWithSHA1, HashAlgorithm.sha1, SignatureAlgorithm.dsa);
        addCertSigAlgOID(h, OIWObjectIdentifiers.sha1WithRSA, HashAlgorithm.sha1, SignatureAlgorithm.rsa);

        addCertSigAlgOID(h, PKCSObjectIdentifiers.sha1WithRSAEncryption, HashAlgorithm.sha1, SignatureAlgorithm.rsa);
        addCertSigAlgOID(h, PKCSObjectIdentifiers.sha224WithRSAEncryption, HashAlgorithm.sha224, SignatureAlgorithm.rsa);
        addCertSigAlgOID(h, PKCSObjectIdentifiers.sha256WithRSAEncryption, HashAlgorithm.sha256, SignatureAlgorithm.rsa);
        addCertSigAlgOID(h, PKCSObjectIdentifiers.sha384WithRSAEncryption, HashAlgorithm.sha384, SignatureAlgorithm.rsa);
        addCertSigAlgOID(h, PKCSObjectIdentifiers.sha512WithRSAEncryption, HashAlgorithm.sha512, SignatureAlgorithm.rsa);

        addCertSigAlgOID(h, X9ObjectIdentifiers.ecdsa_with_SHA1, HashAlgorithm.sha1, SignatureAlgorithm.ecdsa);
        addCertSigAlgOID(h, X9ObjectIdentifiers.ecdsa_with_SHA224, HashAlgorithm.sha224, SignatureAlgorithm.ecdsa);
        addCertSigAlgOID(h, X9ObjectIdentifiers.ecdsa_with_SHA256, HashAlgorithm.sha256, SignatureAlgorithm.ecdsa);
        addCertSigAlgOID(h, X9ObjectIdentifiers.ecdsa_with_SHA384, HashAlgorithm.sha384, SignatureAlgorithm.ecdsa);
        addCertSigAlgOID(h, X9ObjectIdentifiers.ecdsa_with_SHA512, HashAlgorithm.sha512, SignatureAlgorithm.ecdsa);
        addCertSigAlgOID(h, X9ObjectIdentifiers.id_dsa_with_sha1, HashAlgorithm.sha1, SignatureAlgorithm.dsa);

        addCertSigAlgOID(h, EACObjectIdentifiers.id_TA_ECDSA_SHA_1, HashAlgorithm.sha1, SignatureAlgorithm.ecdsa);
        addCertSigAlgOID(h, EACObjectIdentifiers.id_TA_ECDSA_SHA_224, HashAlgorithm.sha224, SignatureAlgorithm.ecdsa);
        addCertSigAlgOID(h, EACObjectIdentifiers.id_TA_ECDSA_SHA_256, HashAlgorithm.sha256, SignatureAlgorithm.ecdsa);
        addCertSigAlgOID(h, EACObjectIdentifiers.id_TA_ECDSA_SHA_384, HashAlgorithm.sha384, SignatureAlgorithm.ecdsa);
        addCertSigAlgOID(h, EACObjectIdentifiers.id_TA_ECDSA_SHA_512, HashAlgorithm.sha512, SignatureAlgorithm.ecdsa);
        addCertSigAlgOID(h, EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_1, HashAlgorithm.sha1, SignatureAlgorithm.rsa);
        addCertSigAlgOID(h, EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_256, HashAlgorithm.sha256, SignatureAlgorithm.rsa);

        addCertSigAlgOID(h, BSIObjectIdentifiers.ecdsa_plain_SHA1, HashAlgorithm.sha1, SignatureAlgorithm.ecdsa);
        addCertSigAlgOID(h, BSIObjectIdentifiers.ecdsa_plain_SHA224, HashAlgorithm.sha224, SignatureAlgorithm.ecdsa);
        addCertSigAlgOID(h, BSIObjectIdentifiers.ecdsa_plain_SHA256, HashAlgorithm.sha256, SignatureAlgorithm.ecdsa);
        addCertSigAlgOID(h, BSIObjectIdentifiers.ecdsa_plain_SHA384, HashAlgorithm.sha384, SignatureAlgorithm.ecdsa);
        addCertSigAlgOID(h, BSIObjectIdentifiers.ecdsa_plain_SHA512, HashAlgorithm.sha512, SignatureAlgorithm.ecdsa);

        addCertSigAlgOID(h, EdECObjectIdentifiers.id_Ed25519, HashAlgorithm.Intrinsic, SignatureAlgorithm.ed25519);
        addCertSigAlgOID(h, EdECObjectIdentifiers.id_Ed448, HashAlgorithm.Intrinsic, SignatureAlgorithm.ed448);

        return h;
    }

    private static Vector createDefaultSupportedSigAlgs()
    {
        Vector result = new Vector();
        result.addElement(SignatureAndHashAlgorithm.ed25519);
        result.addElement(SignatureAndHashAlgorithm.ed448);
        result.addElement(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa));
        result.addElement(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha384, SignatureAlgorithm.ecdsa));
        result.addElement(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha512, SignatureAlgorithm.ecdsa));
        result.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
        result.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha384);
        result.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha512);
        result.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha256);
        result.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha384);
        result.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha512);
        result.addElement(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha256, SignatureAlgorithm.rsa));
        result.addElement(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha384, SignatureAlgorithm.rsa));
        result.addElement(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha512, SignatureAlgorithm.rsa));
        result.addElement(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha256, SignatureAlgorithm.dsa));
        result.addElement(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha384, SignatureAlgorithm.dsa));
        result.addElement(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha512, SignatureAlgorithm.dsa));
        result.addElement(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha224, SignatureAlgorithm.ecdsa));
        result.addElement(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha224, SignatureAlgorithm.rsa));
        result.addElement(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha224, SignatureAlgorithm.dsa));
        result.addElement(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha1, SignatureAlgorithm.ecdsa));
        result.addElement(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha1, SignatureAlgorithm.rsa));
        result.addElement(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha1, SignatureAlgorithm.dsa));
        return result;
    }

    public static final byte[] EMPTY_BYTES = new byte[0];
    public static final short[] EMPTY_SHORTS = new short[0];
    public static final int[] EMPTY_INTS = new int[0];
    public static final long[] EMPTY_LONGS = new long[0];

    protected static short MINIMUM_HASH_STRICT = HashAlgorithm.sha1;
    protected static short MINIMUM_HASH_PREFERRED = HashAlgorithm.sha256;

    public static void checkUint8(short i) throws IOException
    {
        if (!isValidUint8(i))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public static void checkUint8(int i) throws IOException
    {
        if (!isValidUint8(i))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public static void checkUint8(long i) throws IOException
    {
        if (!isValidUint8(i))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public static void checkUint16(int i) throws IOException
    {
        if (!isValidUint16(i))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public static void checkUint16(long i) throws IOException
    {
        if (!isValidUint16(i))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public static void checkUint24(int i) throws IOException
    {
        if (!isValidUint24(i))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public static void checkUint24(long i) throws IOException
    {
        if (!isValidUint24(i))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public static void checkUint32(long i) throws IOException
    {
        if (!isValidUint32(i))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public static void checkUint48(long i) throws IOException
    {
        if (!isValidUint48(i))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public static void checkUint64(long i) throws IOException
    {
        if (!isValidUint64(i))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public static boolean isValidUint8(short i)
    {
        return (i & 0xFF) == i;
    }

    public static boolean isValidUint8(int i)
    {
        return (i & 0xFF) == i;
    }

    public static boolean isValidUint8(long i)
    {
        return (i & 0xFFL) == i;
    }

    public static boolean isValidUint16(int i)
    {
        return (i & 0xFFFF) == i;
    }

    public static boolean isValidUint16(long i)
    {
        return (i & 0xFFFFL) == i;
    }

    public static boolean isValidUint24(int i)
    {
        return (i & 0xFFFFFF) == i;
    }

    public static boolean isValidUint24(long i)
    {
        return (i & 0xFFFFFFL) == i;
    }

    public static boolean isValidUint32(long i)
    {
        return (i & 0xFFFFFFFFL) == i;
    }

    public static boolean isValidUint48(long i)
    {
        return (i & 0xFFFFFFFFFFFFL) == i;
    }

    public static boolean isValidUint64(long i)
    {
        return true;
    }

    public static boolean isSSL(TlsContext context)
    {
        return context.getServerVersion().isSSL();
    }

    public static boolean isTLSv10(ProtocolVersion version)
    {
        return ProtocolVersion.TLSv10.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv10(TlsContext context)
    {
        return isTLSv10(context.getServerVersion());
    }

    public static boolean isTLSv11(ProtocolVersion version)
    {
        return ProtocolVersion.TLSv11.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv11(TlsContext context)
    {
        return isTLSv11(context.getServerVersion());
    }

    public static boolean isTLSv12(ProtocolVersion version)
    {
        return ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv12(TlsContext context)
    {
        return isTLSv12(context.getServerVersion());
    }

    public static boolean isTLSv13(ProtocolVersion version)
    {
        return ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv13(TlsContext context)
    {
        return isTLSv13(context.getServerVersion());
    }

    public static void writeUint8(short i, OutputStream output)
        throws IOException
    {
        output.write(i);
    }

    public static void writeUint8(int i, OutputStream output)
        throws IOException
    {
        output.write(i);
    }

    public static void writeUint8(short i, byte[] buf, int offset)
    {
        buf[offset] = (byte)i;
    }

    public static void writeUint8(int i, byte[] buf, int offset)
    {
        buf[offset] = (byte)i;
    }

    public static void writeUint16(int i, OutputStream output)
        throws IOException
    {
        output.write(i >>> 8);
        output.write(i);
    }

    public static void writeUint16(int i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >>> 8);
        buf[offset + 1] = (byte)i;
    }

    public static void writeUint24(int i, OutputStream output)
        throws IOException
    {
        output.write((byte)(i >>> 16));
        output.write((byte)(i >>> 8));
        output.write((byte)i);
    }

    public static void writeUint24(int i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >>> 16);
        buf[offset + 1] = (byte)(i >>> 8);
        buf[offset + 2] = (byte)i;
    }

    public static void writeUint32(long i, OutputStream output)
        throws IOException
    {
        output.write((byte)(i >>> 24));
        output.write((byte)(i >>> 16));
        output.write((byte)(i >>> 8));
        output.write((byte)i);
    }

    public static void writeUint32(long i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >>> 24);
        buf[offset + 1] = (byte)(i >>> 16);
        buf[offset + 2] = (byte)(i >>> 8);
        buf[offset + 3] = (byte)i;
    }

    public static void writeUint48(long i, OutputStream output)
        throws IOException
    {
        output.write((byte)(i >>> 40));
        output.write((byte)(i >>> 32));
        output.write((byte)(i >>> 24));
        output.write((byte)(i >>> 16));
        output.write((byte)(i >>> 8));
        output.write((byte)i);
    }

    public static void writeUint48(long i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >>> 40);
        buf[offset + 1] = (byte)(i >>> 32);
        buf[offset + 2] = (byte)(i >>> 24);
        buf[offset + 3] = (byte)(i >>> 16);
        buf[offset + 4] = (byte)(i >>> 8);
        buf[offset + 5] = (byte)i;
    }

    public static void writeUint64(long i, OutputStream output)
        throws IOException
    {
        output.write((byte)(i >>> 56));
        output.write((byte)(i >>> 48));
        output.write((byte)(i >>> 40));
        output.write((byte)(i >>> 32));
        output.write((byte)(i >>> 24));
        output.write((byte)(i >>> 16));
        output.write((byte)(i >>> 8));
        output.write((byte)i);
    }

    public static void writeUint64(long i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >>> 56);
        buf[offset + 1] = (byte)(i >>> 48);
        buf[offset + 2] = (byte)(i >>> 40);
        buf[offset + 3] = (byte)(i >>> 32);
        buf[offset + 4] = (byte)(i >>> 24);
        buf[offset + 5] = (byte)(i >>> 16);
        buf[offset + 6] = (byte)(i >>> 8);
        buf[offset + 7] = (byte)i;
    }

    public static void writeOpaque8(byte[] buf, OutputStream output)
        throws IOException
    {
        checkUint8(buf.length);
        writeUint8(buf.length, output);
        output.write(buf);
    }

    public static void writeOpaque8(byte[] data, byte[] buf, int off)
        throws IOException
    {
        checkUint8(data.length);
        writeUint8(data.length, buf, off);
        System.arraycopy(data, 0, buf, off + 1, data.length);
    }

    public static void writeOpaque16(byte[] buf, OutputStream output)
        throws IOException
    {
        checkUint16(buf.length);
        writeUint16(buf.length, output);
        output.write(buf);
    }

    public static void writeOpaque24(byte[] buf, OutputStream output)
        throws IOException
    {
        checkUint24(buf.length);
        writeUint24(buf.length, output);
        output.write(buf);
    }

    public static void writeUint8Array(short[] uints, OutputStream output)
        throws IOException
    {
        for (int i = 0; i < uints.length; ++i)
        {
            writeUint8(uints[i], output);
        }
    }

    public static void writeUint8Array(short[] uints, byte[] buf, int offset)
        throws IOException
    {
        for (int i = 0; i < uints.length; ++i)
        {
            writeUint8(uints[i], buf, offset);
            ++offset;
        }
    }

    public static void writeUint8ArrayWithUint8Length(short[] uints, OutputStream output)
        throws IOException
    {
        checkUint8(uints.length);
        writeUint8(uints.length, output);
        writeUint8Array(uints, output);
    }

    public static void writeUint8ArrayWithUint8Length(short[] uints, byte[] buf, int offset)
        throws IOException
    {
        checkUint8(uints.length);
        writeUint8(uints.length, buf, offset);
        writeUint8Array(uints, buf, offset + 1);
    }

    public static void writeUint16Array(int[] uints, OutputStream output)
        throws IOException
    {
        for (int i = 0; i < uints.length; ++i)
        {
            writeUint16(uints[i], output);
        }
    }

    public static void writeUint16Array(int[] uints, byte[] buf, int offset)
        throws IOException
    {
        for (int i = 0; i < uints.length; ++i)
        {
            writeUint16(uints[i], buf, offset);
            offset += 2;
        }
    }

    public static void writeUint16ArrayWithUint16Length(int[] uints, OutputStream output)
        throws IOException
    {
        int length = 2 * uints.length;
        checkUint16(length);
        writeUint16(length, output);
        writeUint16Array(uints, output);
    }

    public static void writeUint16ArrayWithUint16Length(int[] uints, byte[] buf, int offset)
        throws IOException
    {
        int length = 2 * uints.length;
        checkUint16(length);
        writeUint16(length, buf, offset);
        writeUint16Array(uints, buf, offset + 2);
    }

    public static byte[] decodeOpaque8(byte[] buf)
        throws IOException
    {
        return decodeOpaque8(buf, 0);
    }

    public static byte[] decodeOpaque8(byte[] buf, int minLength)
        throws IOException
    {
        if (buf == null)
        {
            throw new IllegalArgumentException("'buf' cannot be null");
        }
        if (buf.length < 1)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        short length = readUint8(buf, 0);
        if (buf.length != (length + 1) || length < minLength)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        return copyOfRangeExact(buf, 1, buf.length);
    }

    public static byte[] decodeOpaque16(byte[] buf)
        throws IOException
    {
        return decodeOpaque16(buf, 0);
    }

    public static byte[] decodeOpaque16(byte[] buf, int minLength)
        throws IOException
    {
        if (buf == null)
        {
            throw new IllegalArgumentException("'buf' cannot be null");
        }
        if (buf.length < 2)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        int length = readUint16(buf, 0);
        if (buf.length != (length + 2) || length < minLength)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        return copyOfRangeExact(buf, 2, buf.length);
    }

    public static short decodeUint8(byte[] buf) throws IOException
    {
        if (buf == null)
        {
            throw new IllegalArgumentException("'buf' cannot be null");
        }
        if (buf.length != 1)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        return readUint8(buf, 0);
    }

    public static short[] decodeUint8ArrayWithUint8Length(byte[] buf) throws IOException
    {
        if (buf == null)
        {
            throw new IllegalArgumentException("'buf' cannot be null");
        }

        int count = readUint8(buf, 0);
        if (buf.length != (count + 1))
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        short[] uints = new short[count];
        for (int i = 0; i < count; ++i)
        {
            uints[i] = readUint8(buf, i + 1);
        }
        return uints;
    }

    public static int decodeUint16(byte[] buf) throws IOException
    {
        if (buf == null)
        {
            throw new IllegalArgumentException("'buf' cannot be null");
        }
        if (buf.length != 2)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        return readUint16(buf, 0);
    }

    public static long decodeUint32(byte[] buf) throws IOException
    {
        if (buf == null)
        {
            throw new IllegalArgumentException("'buf' cannot be null");
        }
        if (buf.length != 4)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        return readUint32(buf, 0);
    }

    public static byte[] encodeOpaque8(byte[] buf)
        throws IOException
    {
        checkUint8(buf.length);
        return Arrays.prepend(buf, (byte)buf.length);
    }

    public static byte[] encodeOpaque16(byte[] buf)
        throws IOException
    {
        return Arrays.concatenate(encodeUint16(buf.length), buf);
    }

    public static byte[] encodeUint8(short uint) throws IOException
    {
        checkUint8(uint);

        byte[] encoding = new byte[1];
        writeUint8(uint, encoding, 0);
        return encoding;
    }

    public static byte[] encodeUint8ArrayWithUint8Length(short[] uints) throws IOException
    {
        byte[] result = new byte[1 + uints.length];
        writeUint8ArrayWithUint8Length(uints, result, 0);
        return result;
    }

    public static byte[] encodeUint16(int uint) throws IOException
    {
        checkUint16(uint);

        byte[] encoding = new byte[2];
        writeUint16(uint, encoding, 0);
        return encoding;
    }

    public static byte[] encodeUint16ArrayWithUint16Length(int[] uints) throws IOException
    {
        int length = 2 * uints.length;
        byte[] result = new byte[2 + length];
        writeUint16ArrayWithUint16Length(uints, result, 0);
        return result;
    }

    public static byte[] encodeUint32(long uint) throws IOException
    {
        checkUint32(uint);

        byte[] encoding = new byte[4];
        writeUint32(uint, encoding, 0);
        return encoding;
    }

    public static byte[] encodeVersion(ProtocolVersion version) throws IOException
    {
        return new byte[]{
            (byte)version.getMajorVersion(),
            (byte)version.getMinorVersion()
        };
    }

    public static int readInt32(byte[] buf, int offset)
    {
        int n = buf[offset] << 24;
        n |= (buf[++offset] & 0xff) << 16;
        n |= (buf[++offset] & 0xff) << 8;
        n |= (buf[++offset] & 0xff);
        return n;
    }

    public static short readUint8(InputStream input)
        throws IOException
    {
        int i = input.read();
        if (i < 0)
        {
            throw new EOFException();
        }
        return (short)i;
    }

    public static short readUint8(byte[] buf, int offset)
    {
        return (short)(buf[offset] & 0xff);
    }

    public static int readUint16(InputStream input)
        throws IOException
    {
        int i1 = input.read();
        int i2 = input.read();
        if (i2 < 0)
        {
            throw new EOFException();
        }
        return (i1 << 8) | i2;
    }

    public static int readUint16(byte[] buf, int offset)
    {
        int n = (buf[offset] & 0xff) << 8;
        n |= (buf[++offset] & 0xff);
        return n;
    }

    public static int readUint24(InputStream input)
        throws IOException
    {
        int i1 = input.read();
        int i2 = input.read();
        int i3 = input.read();
        if (i3 < 0)
        {
            throw new EOFException();
        }
        return (i1 << 16) | (i2 << 8) | i3;
    }

    public static int readUint24(byte[] buf, int offset)
    {
        int n = (buf[offset] & 0xff) << 16;
        n |= (buf[++offset] & 0xff) << 8;
        n |= (buf[++offset] & 0xff);
        return n;
    }

    public static long readUint32(InputStream input)
        throws IOException
    {
        int i1 = input.read();
        int i2 = input.read();
        int i3 = input.read();
        int i4 = input.read();
        if (i4 < 0)
        {
            throw new EOFException();
        }
        return ((i1 << 24) | (i2 << 16) | (i3 << 8) | i4) & 0xFFFFFFFFL;
    }

    public static long readUint32(byte[] buf, int offset)
    {
        int n = (buf[offset] & 0xff) << 24;
        n |= (buf[++offset] & 0xff) << 16;
        n |= (buf[++offset] & 0xff) << 8;
        n |= (buf[++offset] & 0xff);
        return n & 0xFFFFFFFFL;
    }

    public static long readUint48(InputStream input)
        throws IOException
    {
        int hi = readUint24(input);
        int lo = readUint24(input);
        return ((long)(hi & 0xffffffffL) << 24) | (long)(lo & 0xffffffffL);
    }

    public static long readUint48(byte[] buf, int offset)
    {
        int hi = readUint24(buf, offset);
        int lo = readUint24(buf, offset + 3);
        return ((long)(hi & 0xffffffffL) << 24) | (long)(lo & 0xffffffffL);
    }

    public static byte[] readAllOrNothing(int length, InputStream input)
        throws IOException
    {
        if (length < 1)
        {
            return EMPTY_BYTES;
        }
        byte[] buf = new byte[length];
        int read = Streams.readFully(input, buf);
        if (read == 0)
        {
            return null;
        }
        if (read != length)
        {
            throw new EOFException();
        }
        return buf;
    }

    public static byte[] readFully(int length, InputStream input)
        throws IOException
    {
        if (length < 1)
        {
            return EMPTY_BYTES;
        }
        byte[] buf = new byte[length];
        if (length != Streams.readFully(input, buf))
        {
            throw new EOFException();
        }
        return buf;
    }

    public static void readFully(byte[] buf, InputStream input)
        throws IOException
    {
        int length = buf.length;
        if (length > 0 && length != Streams.readFully(input, buf))
        {
            throw new EOFException();
        }
    }

    public static byte[] readOpaque8(InputStream input)
        throws IOException
    {
        short length = readUint8(input);
        return readFully(length, input);
    }

    public static byte[] readOpaque8(InputStream input, int minLength)
        throws IOException
    {
        short length = readUint8(input);
        if (length < minLength)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        return readFully(length, input);
    }

    public static byte[] readOpaque8(InputStream input, int minLength, int maxLength)
        throws IOException
    {
        short length = readUint8(input);
        if (length < minLength || maxLength < length)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        return readFully(length, input);
    }

    public static byte[] readOpaque16(InputStream input)
        throws IOException
    {
        int length = readUint16(input);
        return readFully(length, input);
    }

    public static byte[] readOpaque16(InputStream input, int minLength)
        throws IOException
    {
        int length = readUint16(input);
        if (length < minLength)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        return readFully(length, input);
    }

    public static byte[] readOpaque24(InputStream input)
        throws IOException
    {
        int length = readUint24(input);
        return readFully(length, input);
    }

    public static byte[] readOpaque24(InputStream input, int minLength)
        throws IOException
    {
        int length = readUint24(input);
        if (length < minLength)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        return readFully(length, input);
    }

    public static short[] readUint8Array(int count, InputStream input)
        throws IOException
    {
        short[] uints = new short[count];
        for (int i = 0; i < count; ++i)
        {
            uints[i] = readUint8(input);
        }
        return uints;
    }

    public static short[] readUint8ArrayWithUint8Length(InputStream input, int minLength)
        throws IOException
    {
        int length = TlsUtils.readUint8(input);
        if (length < minLength)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        return readUint8Array(length, input);
    }

    public static int[] readUint16Array(int count, InputStream input)
        throws IOException
    {
        int[] uints = new int[count];
        for (int i = 0; i < count; ++i)
        {
            uints[i] = readUint16(input);
        }
        return uints;
    }

    public static ProtocolVersion readVersion(byte[] buf, int offset)
    {
        return ProtocolVersion.get(buf[offset] & 0xFF, buf[offset + 1] & 0xFF);
    }

    public static ProtocolVersion readVersion(InputStream input)
        throws IOException
    {
        int i1 = input.read();
        int i2 = input.read();
        if (i2 < 0)
        {
            throw new EOFException();
        }

        return ProtocolVersion.get(i1, i2);
    }

    public static ASN1Primitive readASN1Object(byte[] encoding) throws IOException
    {
        ASN1InputStream asn1 = new ASN1InputStream(encoding);
        ASN1Primitive result = asn1.readObject();
        if (null == result)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        if (null != asn1.readObject())
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        return result;
    }

    public static ASN1Primitive readDERObject(byte[] encoding) throws IOException
    {
        /*
         * NOTE: The current ASN.1 parsing code can't enforce DER-only parsing, but since DER is
         * canonical, we can check it by re-encoding the result and comparing to the original.
         */
        ASN1Primitive result = readASN1Object(encoding);
        byte[] check = result.getEncoded(ASN1Encoding.DER);
        if (!Arrays.areEqual(check, encoding))
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        return result;
    }

    public static void writeGMTUnixTime(byte[] buf, int offset)
    {
        int t = (int)(System.currentTimeMillis() / 1000L);
        buf[offset] = (byte)(t >>> 24);
        buf[offset + 1] = (byte)(t >>> 16);
        buf[offset + 2] = (byte)(t >>> 8);
        buf[offset + 3] = (byte)t;
    }

    public static void writeVersion(ProtocolVersion version, OutputStream output)
        throws IOException
    {
        output.write(version.getMajorVersion());
        output.write(version.getMinorVersion());
    }

    public static void writeVersion(ProtocolVersion version, byte[] buf, int offset)
    {
        buf[offset] = (byte)version.getMajorVersion();
        buf[offset + 1] = (byte)version.getMinorVersion();
    }

    public static void addIfSupported(Vector supportedAlgs, TlsCrypto crypto, SignatureAndHashAlgorithm alg)
    {
        if (crypto.hasSignatureAndHashAlgorithm(alg))
        {
            supportedAlgs.addElement(alg);
        }
    }

    public static void addIfSupported(Vector supportedGroups, TlsCrypto crypto, int namedGroup)
    {
        if (crypto.hasNamedGroup(namedGroup))
        {
            supportedGroups.addElement(Integers.valueOf(namedGroup));
        }
    }

    public static void addIfSupported(Vector supportedGroups, TlsCrypto crypto, int[] namedGroups)
    {
        for (int i = 0; i < namedGroups.length; ++i)
        {
            addIfSupported(supportedGroups, crypto, namedGroups[i]);
        }
    }

    public static boolean addToSet(Vector s, int i)
    {
        boolean result = !s.contains(Integers.valueOf(i));
        if (result)
        {
            s.add(Integers.valueOf(i));
        }
        return result;
    }

    public static Vector getDefaultDSSSignatureAlgorithms()
    {
        return getDefaultSignatureAlgorithms(SignatureAlgorithm.dsa);
    }

    public static Vector getDefaultECDSASignatureAlgorithms()
    {
        return getDefaultSignatureAlgorithms(SignatureAlgorithm.ecdsa);
    }

    public static Vector getDefaultRSASignatureAlgorithms()
    {
        return getDefaultSignatureAlgorithms(SignatureAlgorithm.rsa);
    }

    public static SignatureAndHashAlgorithm getDefaultSignatureAlgorithm(short signatureAlgorithm)
    {
        /*
         * RFC 5246 7.4.1.4.1. If the client does not send the signature_algorithms extension,
         * the server MUST do the following:
         * 
         * - If the negotiated key exchange algorithm is one of (RSA, DHE_RSA, DH_RSA, RSA_PSK,
         * ECDH_RSA, ECDHE_RSA), behave as if client had sent the value {sha1,rsa}.
         * 
         * - If the negotiated key exchange algorithm is one of (DHE_DSS, DH_DSS), behave as if
         * the client had sent the value {sha1,dsa}.
         * 
         * - If the negotiated key exchange algorithm is one of (ECDH_ECDSA, ECDHE_ECDSA),
         * behave as if the client had sent value {sha1,ecdsa}.
         */

        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.dsa:
        case SignatureAlgorithm.ecdsa:
        case SignatureAlgorithm.rsa:
            return SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha1, signatureAlgorithm);
        default:
            return null;
        }
    }

    public static Vector getDefaultSignatureAlgorithms(short signatureAlgorithm)
    {
        SignatureAndHashAlgorithm sigAndHashAlg = getDefaultSignatureAlgorithm(signatureAlgorithm);

        return null == sigAndHashAlg ? new Vector() : vectorOfOne(sigAndHashAlg);
    }

    public static Vector getDefaultSupportedSignatureAlgorithms(TlsContext context)
    {
        TlsCrypto crypto = context.getCrypto();

        int count = DEFAULT_SUPPORTED_SIG_ALGS.size();
        Vector result = new Vector(count);
        for (int i = 0; i < count; ++i)
        {
            addIfSupported(result, crypto, (SignatureAndHashAlgorithm)DEFAULT_SUPPORTED_SIG_ALGS.elementAt(i));
        }
        return result;
    }

    public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(TlsContext context,
        TlsCredentialedSigner signerCredentials)
        throws IOException
    {
        return getSignatureAndHashAlgorithm(context.getServerVersion(), signerCredentials);
    }

    static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(ProtocolVersion negotiatedVersion,
        TlsCredentialedSigner signerCredentials) throws IOException
    {
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
        if (isTLSv12(negotiatedVersion))
        {
            signatureAndHashAlgorithm = signerCredentials.getSignatureAndHashAlgorithm();
            if (signatureAndHashAlgorithm == null)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }
        return signatureAndHashAlgorithm;
    }

    public static byte[] getExtensionData(Hashtable extensions, Integer extensionType)
    {
        return extensions == null ? null : (byte[])extensions.get(extensionType);
    }

    public static boolean hasExpectedEmptyExtensionData(Hashtable extensions, Integer extensionType,
        short alertDescription) throws IOException
    {
        byte[] extension_data = getExtensionData(extensions, extensionType);
        if (extension_data == null)
        {
            return false;
        }
        if (extension_data.length != 0)
        {
            throw new TlsFatalAlert(alertDescription);
        }
        return true;
    }

    public static TlsSession importSession(byte[] sessionID, SessionParameters sessionParameters)
    {
        return new TlsSessionImpl(sessionID, sessionParameters);
    }

    static boolean isExtendedMasterSecretOptionalDTLS(ProtocolVersion[] activeProtocolVersions)
    {
        return ProtocolVersion.contains(activeProtocolVersions, ProtocolVersion.DTLSv12)
            || ProtocolVersion.contains(activeProtocolVersions, ProtocolVersion.DTLSv10);
    }

    static boolean isExtendedMasterSecretOptionalTLS(ProtocolVersion[] activeProtocolVersions)
    {
        return ProtocolVersion.contains(activeProtocolVersions, ProtocolVersion.TLSv12)
            || ProtocolVersion.contains(activeProtocolVersions, ProtocolVersion.TLSv11)
            || ProtocolVersion.contains(activeProtocolVersions, ProtocolVersion.TLSv10);
    }

    public static boolean isNullOrContainsNull(Object[] array)
    {
        if (null == array)
        {
            return true;
        }
        int count = array.length;
        for (int i = 0; i < count; ++i)
        {
            if (null == array[i])
            {
                return true;
            }
        }
        return false;
    }

    public static boolean isNullOrEmpty(byte[] array)
    {
        return null == array || array.length < 1;
    }

    public static boolean isNullOrEmpty(int[] array)
    {
        return null == array || array.length < 1;
    }

    public static boolean isNullOrEmpty(Object[] array)
    {
        return null == array || array.length < 1;
    }

    public static boolean isSignatureAlgorithmsExtensionAllowed(ProtocolVersion version)
    {
        return null != version
            && ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static short getLegacyClientCertType(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.rsa:
            return ClientCertificateType.rsa_sign;
        case SignatureAlgorithm.dsa:
            return ClientCertificateType.dss_sign;
        case SignatureAlgorithm.ecdsa:
            return ClientCertificateType.ecdsa_sign;
        default:
            return -1;
        }
    }

    public static short getLegacySignatureAlgorithmClient(short clientCertificateType)
    {
        switch (clientCertificateType)
        {
        case ClientCertificateType.dss_sign:
            return SignatureAlgorithm.dsa;
        case ClientCertificateType.ecdsa_sign:
            return SignatureAlgorithm.ecdsa;
        case ClientCertificateType.rsa_sign:
            return SignatureAlgorithm.rsa;
        default:
            return -1;
        }
    }

    public static short getLegacySignatureAlgorithmClientCert(short clientCertificateType)
    {
        switch (clientCertificateType)
        {
        case ClientCertificateType.dss_sign:
        case ClientCertificateType.dss_fixed_dh:
            return SignatureAlgorithm.dsa;

        case ClientCertificateType.ecdsa_sign:
        case ClientCertificateType.ecdsa_fixed_ecdh:
            return SignatureAlgorithm.ecdsa;

        case ClientCertificateType.rsa_sign:
        case ClientCertificateType.rsa_fixed_dh:
        case ClientCertificateType.rsa_fixed_ecdh:
            return SignatureAlgorithm.rsa;
        default:
            return -1;
        }
    }

    public static short getLegacySignatureAlgorithmServer(int keyExchangeAlgorithm)
    {
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.SRP_DSS:
            return SignatureAlgorithm.dsa;

        case KeyExchangeAlgorithm.ECDHE_ECDSA:
            return SignatureAlgorithm.ecdsa;

        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        case KeyExchangeAlgorithm.SRP_RSA:
            return SignatureAlgorithm.rsa;

        default:
            return -1;
        }
    }

    public static short getLegacySignatureAlgorithmServerCert(int keyExchangeAlgorithm)
    {
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.SRP_DSS:
            return SignatureAlgorithm.dsa;

        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
            return SignatureAlgorithm.ecdsa;

        case KeyExchangeAlgorithm.DH_RSA:
        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        case KeyExchangeAlgorithm.RSA:
        case KeyExchangeAlgorithm.RSA_PSK:
        case KeyExchangeAlgorithm.SRP_RSA:
            return SignatureAlgorithm.rsa;

        default:
            return -1;
        }
    }

    public static Vector getLegacySupportedSignatureAlgorithms()
    {
        Vector result = new Vector(3);
        result.add(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha1, SignatureAlgorithm.dsa));
        result.add(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha1, SignatureAlgorithm.ecdsa));
        result.add(SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha1, SignatureAlgorithm.rsa));
        return result;
    }

    public static void encodeSupportedSignatureAlgorithms(Vector supportedSignatureAlgorithms, OutputStream output)
        throws IOException
    {
        if (supportedSignatureAlgorithms == null || supportedSignatureAlgorithms.size() < 1
            || supportedSignatureAlgorithms.size() >= (1 << 15))
        {
            throw new IllegalArgumentException(
                "'supportedSignatureAlgorithms' must have length from 1 to (2^15 - 1)");
        }

        // supported_signature_algorithms
        int length = 2 * supportedSignatureAlgorithms.size();
        checkUint16(length);
        writeUint16(length, output);
        for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
        {
            SignatureAndHashAlgorithm entry = (SignatureAndHashAlgorithm)supportedSignatureAlgorithms.elementAt(i);
            if (entry.getSignature() == SignatureAlgorithm.anonymous)
            {
                /*
                 * RFC 5246 7.4.1.4.1 The "anonymous" value is meaningless in this context but used
                 * in Section 7.4.3. It MUST NOT appear in this extension.
                 */
                throw new IllegalArgumentException(
                    "SignatureAlgorithm.anonymous MUST NOT appear in the signature_algorithms extension");
            }
            entry.encode(output);
        }
    }

    public static Vector parseSupportedSignatureAlgorithms(InputStream input)
        throws IOException
    {
        // supported_signature_algorithms
        int length = readUint16(input);
        if (length < 2 || (length & 1) != 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        int count = length / 2;
        Vector supportedSignatureAlgorithms = new Vector(count);
        for (int i = 0; i < count; ++i)
        {
            SignatureAndHashAlgorithm sigAndHashAlg = SignatureAndHashAlgorithm.parse(input);

            if (SignatureAlgorithm.anonymous != sigAndHashAlg.getSignature())
            {
                supportedSignatureAlgorithms.addElement(sigAndHashAlg);
            }
        }
        return supportedSignatureAlgorithms;
    }

    public static void verifySupportedSignatureAlgorithm(Vector supportedSignatureAlgorithms, SignatureAndHashAlgorithm signatureAlgorithm)
        throws IOException
    {
        if (supportedSignatureAlgorithms == null || supportedSignatureAlgorithms.size() < 1
            || supportedSignatureAlgorithms.size() >= (1 << 15))
        {
            throw new IllegalArgumentException(
                "'supportedSignatureAlgorithms' must have length from 1 to (2^15 - 1)");
        }
        if (signatureAlgorithm == null)
        {
            throw new IllegalArgumentException("'signatureAlgorithm' cannot be null");
        }

        if (signatureAlgorithm.getSignature() == SignatureAlgorithm.anonymous
            || !containsSignatureAlgorithm(supportedSignatureAlgorithms, signatureAlgorithm))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
    }

    public static boolean containsSignatureAlgorithm(Vector supportedSignatureAlgorithms, SignatureAndHashAlgorithm signatureAlgorithm)
        throws IOException
    {
        for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
        {
            SignatureAndHashAlgorithm entry = (SignatureAndHashAlgorithm)supportedSignatureAlgorithms.elementAt(i);
            if (entry.getHash() == signatureAlgorithm.getHash() && entry.getSignature() == signatureAlgorithm.getSignature())
            {
                return true;
            }
        }

        return false;
    }

    public static boolean containsAnySignatureAlgorithm(Vector supportedSignatureAlgorithms, short signatureAlgorithm)
    {
        for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
        {
            SignatureAndHashAlgorithm entry = (SignatureAndHashAlgorithm)supportedSignatureAlgorithms.elementAt(i);
            if (entry.getSignature() == signatureAlgorithm)
            {
                return true;
            }
        }

        return false;
    }

    public static TlsSecret PRF(SecurityParameters securityParameters, TlsSecret secret, String asciiLabel, byte[] seed,
        int length)
    {
        return secret.deriveUsingPRF(securityParameters.getPRFAlgorithm(), asciiLabel, seed, length);
    }

    /**
     * @deprecated Use {@link #PRF(SecurityParameters, TlsSecret, String, byte[], int)} instead.
     */
    public static TlsSecret PRF(TlsContext context, TlsSecret secret, String asciiLabel, byte[] seed, int length)
    {
        return PRF(context.getSecurityParametersHandshake(), secret, asciiLabel, seed, length);
    }

    public static byte[] clone(byte[] data)
    {
        return null == data ? (byte[])null : data.length == 0 ? EMPTY_BYTES : (byte[])data.clone();
    }

    public static boolean constantTimeAreEqual(int len, byte[] a, int aOff, byte[] b, int bOff)
    {
        int d = 0;
        for (int i = 0; i < len; ++i)
        {
            d |= (a[aOff + i] ^ b[bOff + i]);
        }
        return 0 == d;
    }

    public static byte[] copyOfRangeExact(byte[] original, int from, int to)
    {
        int newLength = to - from;
        byte[] copy = new byte[newLength];
        System.arraycopy(original, from, copy, 0, newLength);
        return copy;
    }

    static byte[] concat(byte[] a, byte[] b)
    {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    static byte[] calculateEndPointHash(TlsContext context, TlsCertificate certificate, byte[] enc) throws IOException
    {
        return calculateEndPointHash(context, certificate, enc, 0, enc.length);
    }

    static byte[] calculateEndPointHash(TlsContext context, TlsCertificate certificate, byte[] enc, int encOff,
        int encLen) throws IOException
    {
        short hashAlgorithm = HashAlgorithm.none;

        String sigAlgOID = certificate.getSigAlgOID();
        if (sigAlgOID != null)
        {
            if (PKCSObjectIdentifiers.id_RSASSA_PSS.getId().equals(sigAlgOID))
            {
                RSASSAPSSparams pssParams = RSASSAPSSparams.getInstance(certificate.getSigAlgParams());
                if (null != pssParams)
                {
                    ASN1ObjectIdentifier hashOID = pssParams.getHashAlgorithm().getAlgorithm();
                    if (NISTObjectIdentifiers.id_sha256.equals(hashOID))
                    {
                        hashAlgorithm = HashAlgorithm.sha256;
                    }
                    else if (NISTObjectIdentifiers.id_sha384.equals(hashOID))
                    {
                        hashAlgorithm = HashAlgorithm.sha384;
                    }
                    else if (NISTObjectIdentifiers.id_sha512.equals(hashOID))
                    {
                        hashAlgorithm = HashAlgorithm.sha512;
                    }
                }
            }
            else
            {
                SignatureAndHashAlgorithm sigAndHashAlg = (SignatureAndHashAlgorithm)CERT_SIG_ALG_OIDS.get(sigAlgOID);
                if (sigAndHashAlg != null)
                {
                    hashAlgorithm = sigAndHashAlg.getHash();
                }
            }
        }

        switch (hashAlgorithm)
        {
        case HashAlgorithm.Intrinsic:
            hashAlgorithm = HashAlgorithm.none;
            break;
        case HashAlgorithm.md5:
        case HashAlgorithm.sha1:
            hashAlgorithm = HashAlgorithm.sha256;
            break;
        }

        if (HashAlgorithm.none != hashAlgorithm)
        {
            TlsHash hash = context.getCrypto().createHash(hashAlgorithm);
            if (hash != null)
            {                
                hash.update(enc, encOff, encLen);
                return hash.calculateHash();
            }
        }

        return EMPTY_BYTES;
    }

    public static byte[] calculateExporterSeed(SecurityParameters securityParameters, byte[] context)
    {
        byte[] cr = securityParameters.getClientRandom(), sr = securityParameters.getServerRandom();
        if (null == context)
        {
            return Arrays.concatenate(cr, sr);
        }

        if (!isValidUint16(context.length))
        {
            throw new IllegalArgumentException("'context' must have length less than 2^16 (or be null)");
        }

        byte[] contextLength = new byte[2];
        writeUint16(context.length, contextLength, 0);

        return Arrays.concatenate(cr, sr, contextLength, context);
    }

    static TlsSecret calculateMasterSecret(TlsContext context, TlsSecret preMasterSecret)
    {
        SecurityParameters sp = context.getSecurityParametersHandshake();

        String asciiLabel;
        byte[] seed;
        if (sp.isExtendedMasterSecret())
        {
            asciiLabel = ExporterLabel.extended_master_secret;
            seed = sp.getSessionHash();
        }
        else
        {
            asciiLabel = ExporterLabel.master_secret;
            seed = concat(sp.getClientRandom(), sp.getServerRandom());
        }

        return PRF(sp, preMasterSecret, asciiLabel, seed, 48);
    }

    static byte[] calculateVerifyData(TlsContext context, TlsHandshakeHash handshakeHash, boolean isServer)
        throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();

        if (isTLSv13(negotiatedVersion))
        {
            TlsSecret baseKey = isServer
                ?   securityParameters.getBaseKeyServer()
                :   securityParameters.getBaseKeyClient();

            TlsSecret finishedKey = deriveSecret(securityParameters, baseKey, "finished", TlsUtils.EMPTY_BYTES);
            byte[] transcriptHash = getCurrentPRFHash(handshakeHash);

            TlsCrypto crypto = context.getCrypto();
            byte[] hmacKey = crypto.adoptSecret(finishedKey).extract();
            TlsHMAC hmac = crypto.createHMAC(securityParameters.getPRFHashAlgorithm());
            hmac.setKey(hmacKey, 0, hmacKey.length);
            hmac.update(transcriptHash, 0, transcriptHash.length);
            return hmac.calculateMAC();
        }

        if (negotiatedVersion.isSSL())
        {
            return SSL3Utils.calculateVerifyData(handshakeHash, isServer);
        }

        String asciiLabel = isServer ? ExporterLabel.server_finished : ExporterLabel.client_finished;
        byte[] prfHash = getCurrentPRFHash(handshakeHash);

        TlsSecret master_secret = securityParameters.getMasterSecret();
        int verify_data_length = securityParameters.getVerifyDataLength();

        return PRF(securityParameters, master_secret, asciiLabel, prfHash, verify_data_length).extract();
    }

    static void establish13PhaseSecrets(TlsContext context) throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        short hash = securityParameters.getPRFHashAlgorithm();
        int hashLen = securityParameters.getPRFHashLength();
        byte[] zeroes = new byte[hashLen];

        byte[] psk = securityParameters.getPSK();
        if (null == psk)
        {
            psk = zeroes;
        }
        else
        {
            securityParameters.psk = null;
        }

        byte[] ecdhe = zeroes;
        TlsSecret sharedSecret = securityParameters.getSharedSecret();
        if (null != sharedSecret)
        {
            securityParameters.sharedSecret = null;
            ecdhe = sharedSecret.extract();
        }

        TlsCrypto crypto = context.getCrypto();

        byte[] emptyTranscriptHash = crypto.createHash(hash).calculateHash();

        TlsSecret earlySecret = crypto.hkdfInit(hash)
            .hkdfExtract(hash, psk);
        TlsSecret handshakeSecret = deriveSecret(securityParameters, earlySecret, "derived", emptyTranscriptHash)
            .hkdfExtract(hash, ecdhe);
        TlsSecret masterSecret = deriveSecret(securityParameters, handshakeSecret, "derived", emptyTranscriptHash)
            .hkdfExtract(hash, zeroes);

        securityParameters.earlySecret = earlySecret;
        securityParameters.handshakeSecret = handshakeSecret;
        securityParameters.masterSecret = masterSecret;
    }

    private static void establish13TrafficSecrets(TlsContext context, byte[] transcriptHash, TlsSecret phaseSecret,
        String clientLabel, String serverLabel, RecordStream recordStream) throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();

        securityParameters.trafficSecretClient = deriveSecret(securityParameters, phaseSecret, clientLabel,
            transcriptHash);

        if (null != serverLabel)
        {
            securityParameters.trafficSecretServer = deriveSecret(securityParameters, phaseSecret, serverLabel,
                transcriptHash);
        }

        // TODO[tls13] Early data (client->server only)

        recordStream.setPendingCipher(initCipher(context));
    }

    static void establish13PhaseApplication(TlsContext context, byte[] serverFinishedTranscriptHash,
        RecordStream recordStream) throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        TlsSecret phaseSecret = securityParameters.getMasterSecret();

        establish13TrafficSecrets(context, serverFinishedTranscriptHash, phaseSecret, "c ap traffic", "s ap traffic",
            recordStream);

        securityParameters.exporterMasterSecret = deriveSecret(securityParameters, phaseSecret, "exp master",
            serverFinishedTranscriptHash);
    }

    static void establish13PhaseEarly(TlsContext context, byte[] clientHelloTranscriptHash, RecordStream recordStream)
        throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        TlsSecret phaseSecret = securityParameters.getEarlySecret();

        // TODO[tls13] binder_key

        // TODO[tls13] Early data (client->server only)
        if (null != recordStream)
        {
            establish13TrafficSecrets(context, clientHelloTranscriptHash, phaseSecret, "c e traffic", null,
                recordStream);
        }

        securityParameters.earlyExporterMasterSecret = deriveSecret(securityParameters, phaseSecret, "e exp master",
            clientHelloTranscriptHash);
    }

    static void establish13PhaseHandshake(TlsContext context, byte[] serverHelloTranscriptHash,
        RecordStream recordStream) throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        TlsSecret phaseSecret = securityParameters.getHandshakeSecret();

        establish13TrafficSecrets(context, serverHelloTranscriptHash, phaseSecret, "c hs traffic", "s hs traffic",
            recordStream);

        securityParameters.baseKeyClient = securityParameters.getTrafficSecretClient();
        securityParameters.baseKeyServer = securityParameters.getTrafficSecretServer();
    }

    static void update13TrafficSecretLocal(TlsContext context) throws IOException
    {
        update13TrafficSecret(context, context.isServer());
    }

    static void update13TrafficSecretPeer(TlsContext context) throws IOException
    {
        update13TrafficSecret(context, !context.isServer());
    }

    private static void update13TrafficSecret(TlsContext context, boolean forServer) throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParametersConnection();

        TlsSecret current;
        if (forServer)
        {
            current = securityParameters.getTrafficSecretServer();
            securityParameters.trafficSecretServer = update13TrafficSecret(securityParameters, current);
        }
        else
        {
            current = securityParameters.getTrafficSecretClient();
            securityParameters.trafficSecretClient = update13TrafficSecret(securityParameters, current);
        }

        if (null != current)
        {
            current.destroy();
        }
    }

    private static TlsSecret update13TrafficSecret(SecurityParameters securityParameters, TlsSecret secret) throws IOException
    {
        return TlsCryptoUtils.hkdfExpandLabel(secret, securityParameters.getPRFHashAlgorithm(), "traffic upd",
            EMPTY_BYTES, securityParameters.getPRFHashLength());
    }

    public static short getHashAlgorithmForHMACAlgorithm(int macAlgorithm)
    {
        switch (macAlgorithm)
        {
        case MACAlgorithm.hmac_md5:
            return HashAlgorithm.md5;
        case MACAlgorithm.hmac_sha1:
            return HashAlgorithm.sha1;
        case MACAlgorithm.hmac_sha256:
            return HashAlgorithm.sha256;
        case MACAlgorithm.hmac_sha384:
            return HashAlgorithm.sha384;
        case MACAlgorithm.hmac_sha512:
            return HashAlgorithm.sha512;
        default:
            throw new IllegalArgumentException("specified MACAlgorithm not an HMAC: " + MACAlgorithm.getText(macAlgorithm));
        }
    }

    public static short getHashAlgorithmForPRFAlgorithm(int prfAlgorithm)
    {
        switch (prfAlgorithm)
        {
        case PRFAlgorithm.ssl_prf_legacy:
        case PRFAlgorithm.tls_prf_legacy:
            throw new IllegalArgumentException("legacy PRF not a valid algorithm");
        case PRFAlgorithm.tls_prf_sha256:
        case PRFAlgorithm.tls13_hkdf_sha256:
            return HashAlgorithm.sha256;
        case PRFAlgorithm.tls_prf_sha384:
        case PRFAlgorithm.tls13_hkdf_sha384:
            return HashAlgorithm.sha384;
        default:
            throw new IllegalArgumentException("unknown PRFAlgorithm: " + PRFAlgorithm.getText(prfAlgorithm));
        }
    }

    public static ASN1ObjectIdentifier getOIDForHashAlgorithm(short hashAlgorithm)
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithm.md5:
            return PKCSObjectIdentifiers.md5;
        case HashAlgorithm.sha1:
            return X509ObjectIdentifiers.id_SHA1;
        case HashAlgorithm.sha224:
            return NISTObjectIdentifiers.id_sha224;
        case HashAlgorithm.sha256:
            return NISTObjectIdentifiers.id_sha256;
        case HashAlgorithm.sha384:
            return NISTObjectIdentifiers.id_sha384;
        case HashAlgorithm.sha512:
            return NISTObjectIdentifiers.id_sha512;
        default:
            throw new IllegalArgumentException("invalid HashAlgorithm: " + HashAlgorithm.getText(hashAlgorithm));
        }
    }

    static int getPRFAlgorithm(SecurityParameters securityParameters, int cipherSuite) throws IOException
    {
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();

        final boolean isTLSv13 = TlsUtils.isTLSv13(negotiatedVersion);
        final boolean isTLSv12Exactly = !isTLSv13 && TlsUtils.isTLSv12(negotiatedVersion);
        final boolean isSSL = negotiatedVersion.isSSL();

        switch (cipherSuite)
        {
        case CipherSuite.TLS_AES_128_CCM_SHA256:
        case CipherSuite.TLS_AES_128_CCM_8_SHA256:
        case CipherSuite.TLS_AES_128_GCM_SHA256:
        case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
        {
            if (isTLSv13)
            {
                return PRFAlgorithm.tls13_hkdf_sha256;
            }
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        case CipherSuite.TLS_AES_256_GCM_SHA384:
        {
            if (isTLSv13)
            {
                return PRFAlgorithm.tls13_hkdf_sha384;
            }
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
        {
            if (isTLSv12Exactly)
            {
                return PRFAlgorithm.tls_prf_sha256;
            }
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        {
            if (isTLSv12Exactly)
            {
                return PRFAlgorithm.tls_prf_sha384;
            }
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384:
        {
            if (isTLSv13)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
            if (isTLSv12Exactly)
            {
                return PRFAlgorithm.tls_prf_sha384;
            }
            if (isSSL)
            {
                return PRFAlgorithm.ssl_prf_legacy;
            }
            return PRFAlgorithm.tls_prf_legacy;
        }

        default:
        {
            if (isTLSv13)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
            if (isTLSv12Exactly)
            {
                return PRFAlgorithm.tls_prf_sha256;
            }
            if (isSSL)
            {
                return PRFAlgorithm.ssl_prf_legacy;
            }
            return PRFAlgorithm.tls_prf_legacy;
        }
        }
    }

    static byte[] calculateSignatureHash(TlsContext context, SignatureAndHashAlgorithm algorithm, DigestInputBuffer buf)
    {
        TlsCrypto crypto = context.getCrypto();

        TlsHash h = algorithm == null
            ? new CombinedHash(crypto)
            : crypto.createHash(algorithm.getHash());

        SecurityParameters sp = context.getSecurityParametersHandshake();
        byte[] cr = sp.getClientRandom(), sr = sp.getServerRandom();
        h.update(cr, 0, cr.length);
        h.update(sr, 0, sr.length);
        buf.updateDigest(h);

        return h.calculateHash();
    }

    static void sendSignatureInput(TlsContext context, DigestInputBuffer buf, OutputStream output)
        throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        // NOTE: The implicit copy here is intended (and important)
        output.write(Arrays.concatenate(securityParameters.getClientRandom(), securityParameters.getServerRandom()));
        buf.copyTo(output);
        output.close();
    }

    static DigitallySigned generateCertificateVerifyClient(TlsClientContext clientContext,
        TlsCredentialedSigner credentialedSigner, TlsStreamSigner streamSigner, TlsHandshakeHash handshakeHash)
        throws IOException
    {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();

        if (isTLSv13(negotiatedVersion))
        {
            //  Should be using generateCertificateVerify13 instead
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        /*
         * RFC 5246 4.7. digitally-signed element needs SignatureAndHashAlgorithm from TLS 1.2
         */
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = getSignatureAndHashAlgorithm(negotiatedVersion,
            credentialedSigner);

        byte[] signature;
        if (streamSigner != null)
        {
            handshakeHash.copyBufferTo(streamSigner.getOutputStream());
            signature = streamSigner.getSignature();
        }
        else
        {
            byte[] hash;
            if (signatureAndHashAlgorithm == null)
            {
                hash = securityParameters.getSessionHash();
            }
            else
            {
                hash = handshakeHash.getFinalHash(signatureAndHashAlgorithm.getHash());
            }

            signature = credentialedSigner.generateRawSignature(hash);
        }

        return new DigitallySigned(signatureAndHashAlgorithm, signature);
    }

    static DigitallySigned generate13CertificateVerify(TlsContext context, TlsCredentialedSigner credentialedSigner,
        TlsHandshakeHash handshakeHash) throws IOException
    {
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = credentialedSigner.getSignatureAndHashAlgorithm();
        if (null == signatureAndHashAlgorithm)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        String contextString = context.isServer()
            ? "TLS 1.3, server CertificateVerify"
            : "TLS 1.3, client CertificateVerify";

        byte[] signature = generate13CertificateVerify(context.getCrypto(), credentialedSigner, contextString,
            handshakeHash, signatureAndHashAlgorithm.getHash());

        return new DigitallySigned(signatureAndHashAlgorithm, signature);
    }

    private static byte[] generate13CertificateVerify(TlsCrypto crypto, TlsCredentialedSigner credentialedSigner,
        String contextString, TlsHandshakeHash handshakeHash, short hashAlgorithm) throws IOException
    {
        TlsStreamSigner streamSigner = credentialedSigner.getStreamSigner();

        byte[] header = getCertificateVerifyHeader(contextString);
        byte[] prfHash = getCurrentPRFHash(handshakeHash);

        if (null != streamSigner)
        {
            OutputStream output = streamSigner.getOutputStream();
            output.write(header, 0, header.length);
            output.write(prfHash, 0, prfHash.length);
            return streamSigner.getSignature();
        }

        TlsHash tlsHash = crypto.createHash(hashAlgorithm);
        tlsHash.update(header, 0, header.length);
        tlsHash.update(prfHash, 0, prfHash.length);
        byte[] hash = tlsHash.calculateHash();
        return credentialedSigner.generateRawSignature(hash);
    }

    static void verifyCertificateVerifyClient(TlsServerContext serverContext, CertificateRequest certificateRequest,
        DigitallySigned certificateVerify, TlsHandshakeHash handshakeHash) throws IOException
    {
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();
        Certificate clientCertificate = securityParameters.getPeerCertificate();
        TlsCertificate verifyingCert = clientCertificate.getCertificateAt(0);
        SignatureAndHashAlgorithm sigAndHashAlg = certificateVerify.getAlgorithm();
        short signatureAlgorithm;

        if (null == sigAndHashAlg)
        {
            signatureAlgorithm = verifyingCert.getLegacySignatureAlgorithm();

            short clientCertType = getLegacyClientCertType(signatureAlgorithm);
            if (clientCertType < 0 || !Arrays.contains(certificateRequest.getCertificateTypes(), clientCertType))
            {
                throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
            }
        }
        else
        {
            signatureAlgorithm = sigAndHashAlg.getSignature();

            // TODO Is it possible (maybe only pre-1.2 to check this immediately when the Certificate arrives?
            if (!isValidSignatureAlgorithmForCertificateVerify(signatureAlgorithm, certificateRequest.getCertificateTypes()))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            verifySupportedSignatureAlgorithm(securityParameters.getServerSigAlgs(), sigAndHashAlg);
        }

        // Verify the CertificateVerify message contains a correct signature.
        boolean verified;
        try
        {
            TlsVerifier verifier = verifyingCert.createVerifier(signatureAlgorithm);
            if (isTLSv13(securityParameters.getNegotiatedVersion()))
            {
                verified = verify13CertificateVerify(serverContext.getCrypto(), certificateVerify, verifier,
                    "TLS 1.3, client CertificateVerify", handshakeHash);
            }
            else
            {
                TlsStreamVerifier streamVerifier = verifier.getStreamVerifier(certificateVerify);

                if (streamVerifier != null)
                {
                    handshakeHash.copyBufferTo(streamVerifier.getOutputStream());
                    verified = streamVerifier.isVerified();
                }
                else
                {
                    byte[] hash;
                    if (isTLSv12(serverContext))
                    {
                        hash = handshakeHash.getFinalHash(sigAndHashAlg.getHash());
                    }
                    else
                    {
                        hash = securityParameters.getSessionHash();
                    }

                    verified = verifier.verifyRawSignature(certificateVerify, hash);
                }
            }
        }
        catch (TlsFatalAlert e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.decrypt_error, e);
        }

        if (!verified)
        {
            throw new TlsFatalAlert(AlertDescription.decrypt_error);
        }
    }

    static void verify13CertificateVerifyClient(TlsServerContext serverContext, CertificateRequest certificateRequest,
        DigitallySigned certificateVerify, TlsHandshakeHash handshakeHash) throws IOException
    {
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();
        Certificate clientCertificate = securityParameters.getPeerCertificate();
        TlsCertificate verifyingCert = clientCertificate.getCertificateAt(0);

        SignatureAndHashAlgorithm sigAndHashAlg = certificateVerify.getAlgorithm();
        verifySupportedSignatureAlgorithm(securityParameters.getServerSigAlgs(), sigAndHashAlg);

        short signatureAlgorithm = sigAndHashAlg.getSignature();

        // Verify the CertificateVerify message contains a correct signature.
        boolean verified;
        try
        {
            TlsVerifier verifier = verifyingCert.createVerifier(signatureAlgorithm);

            verified = verify13CertificateVerify(serverContext.getCrypto(), certificateVerify, verifier,
                "TLS 1.3, client CertificateVerify", handshakeHash);
        }
        catch (TlsFatalAlert e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.decrypt_error, e);
        }

        if (!verified)
        {
            throw new TlsFatalAlert(AlertDescription.decrypt_error);
        }
    }

    static void verify13CertificateVerifyServer(TlsClientContext clientContext, DigitallySigned certificateVerify,
        TlsHandshakeHash handshakeHash) throws IOException
    {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        Certificate serverCertificate = securityParameters.getPeerCertificate();
        TlsCertificate verifyingCert = serverCertificate.getCertificateAt(0);

        SignatureAndHashAlgorithm sigAndHashAlg = certificateVerify.getAlgorithm();
        verifySupportedSignatureAlgorithm(securityParameters.getClientSigAlgs(), sigAndHashAlg);

        short signatureAlgorithm = sigAndHashAlg.getSignature();

        // Verify the CertificateVerify message contains a correct signature.
        boolean verified;
        try
        {
            TlsVerifier verifier = verifyingCert.createVerifier(signatureAlgorithm);

            verified = verify13CertificateVerify(clientContext.getCrypto(), certificateVerify, verifier,
                "TLS 1.3, server CertificateVerify", handshakeHash);
        }
        catch (TlsFatalAlert e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.decrypt_error, e);
        }

        if (!verified)
        {
            throw new TlsFatalAlert(AlertDescription.decrypt_error);
        }
    }

    private static boolean verify13CertificateVerify(TlsCrypto crypto, DigitallySigned certificateVerify,
        TlsVerifier verifier, String contextString, TlsHandshakeHash handshakeHash) throws IOException
    {
        TlsStreamVerifier streamVerifier = verifier.getStreamVerifier(certificateVerify);

        byte[] header = getCertificateVerifyHeader(contextString);
        byte[] prfHash = getCurrentPRFHash(handshakeHash);

        if (null != streamVerifier)
        {
            OutputStream output = streamVerifier.getOutputStream();
            output.write(header, 0, header.length);
            output.write(prfHash, 0, prfHash.length);
            return streamVerifier.isVerified();
        }

        TlsHash tlsHash = crypto.createHash(certificateVerify.getAlgorithm().getHash());
        tlsHash.update(header, 0, header.length);
        tlsHash.update(prfHash, 0, prfHash.length);
        byte[] hash = tlsHash.calculateHash();
        return verifier.verifyRawSignature(certificateVerify, hash);
    }

    private static byte[] getCertificateVerifyHeader(String contextString)
    {
        int count = contextString.length();
        byte[] header = new byte[64 + count + 1];
        for (int i = 0; i < 64; ++i)
        {
            header[i] = 0x20;
        }
        for (int i = 0; i < count; ++i)
        {
            char c = contextString.charAt(i);
            header[64 + i] = (byte)c;
        }
        header[64 + count] = 0x00;
        return header;
    }

    static void generateServerKeyExchangeSignature(TlsContext context, TlsCredentialedSigner credentials,
        DigestInputBuffer digestBuffer) throws IOException
    {
        /*
         * RFC 5246 4.7. digitally-signed element needs SignatureAndHashAlgorithm from TLS 1.2
         */
        SignatureAndHashAlgorithm algorithm = getSignatureAndHashAlgorithm(context, credentials);
        TlsStreamSigner streamSigner = credentials.getStreamSigner();

        byte[] signature;
        if (streamSigner != null)
        {
            sendSignatureInput(context, digestBuffer, streamSigner.getOutputStream());
            signature = streamSigner.getSignature();
        }
        else
        {
            byte[] hash = calculateSignatureHash(context, algorithm, digestBuffer);
            signature = credentials.generateRawSignature(hash);
        }

        DigitallySigned digitallySigned = new DigitallySigned(algorithm, signature);

        digitallySigned.encode(digestBuffer);
    }

    static void verifyServerKeyExchangeSignature(TlsContext context, InputStream signatureInput,
        TlsCertificate serverCertificate, DigestInputBuffer digestBuffer) throws IOException
    {
        DigitallySigned digitallySigned = DigitallySigned.parse(context, signatureInput);

        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        int keyExchangeAlgorithm = securityParameters.getKeyExchangeAlgorithm();

        SignatureAndHashAlgorithm sigAndHashAlg = digitallySigned.getAlgorithm();
        short signatureAlgorithm;

        if (sigAndHashAlg == null)
        {
            signatureAlgorithm = getLegacySignatureAlgorithmServer(keyExchangeAlgorithm);
        }
        else
        {
            signatureAlgorithm = sigAndHashAlg.getSignature();

            if (!isValidSignatureAlgorithmForServerKeyExchange(signatureAlgorithm, keyExchangeAlgorithm))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            verifySupportedSignatureAlgorithm(securityParameters.getClientSigAlgs(), sigAndHashAlg);
        }

        TlsVerifier verifier = serverCertificate.createVerifier(signatureAlgorithm);
        TlsStreamVerifier streamVerifier = verifier.getStreamVerifier(digitallySigned);

        boolean verified;
        if (streamVerifier != null)
        {
            sendSignatureInput(context, digestBuffer, streamVerifier.getOutputStream());
            verified = streamVerifier.isVerified();
        }
        else
        {
            byte[] hash = calculateSignatureHash(context, sigAndHashAlg, digestBuffer);
            verified = verifier.verifyRawSignature(digitallySigned, hash);
        }

        if (!verified)
        {
            throw new TlsFatalAlert(AlertDescription.decrypt_error);
        }
    }

    static void trackHashAlgorithms(TlsHandshakeHash handshakeHash, Vector supportedSignatureAlgorithms)
    {
        if (supportedSignatureAlgorithms != null)
        {
            for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
            {
                SignatureAndHashAlgorithm signatureAndHashAlgorithm = (SignatureAndHashAlgorithm)
                    supportedSignatureAlgorithms.elementAt(i);
                short hashAlgorithm = signatureAndHashAlgorithm.getHash();

                if (HashAlgorithm.Intrinsic == hashAlgorithm)
                {
                    // TODO[RFC 8422]
                    handshakeHash.forceBuffering();
                }
                else if (HashAlgorithm.isRecognized(hashAlgorithm))
                {
                    handshakeHash.trackHashAlgorithm(hashAlgorithm);
                }
                else //if (HashAlgorithm.isPrivate(hashAlgorithm))
                {
                    // TODO Support values in the "Reserved for Private Use" range
                }
            }
        }
    }

    public static boolean hasSigningCapability(short clientCertificateType)
    {
        switch (clientCertificateType)
        {
        case ClientCertificateType.dss_sign:
        case ClientCertificateType.ecdsa_sign:
        case ClientCertificateType.rsa_sign:
            return true;
        default:
            return false;
        }
    }

    public static Vector vectorOfOne(Object obj)
    {
        Vector v = new Vector(1);
        v.addElement(obj);
        return v;
    }

    public static int getCipherType(int cipherSuite)
    {
        int encryptionAlgorithm = getEncryptionAlgorithm(cipherSuite);

        return getEncryptionAlgorithmType(encryptionAlgorithm);
    }

    public static int getEncryptionAlgorithm(int cipherSuite)
    {
        switch (cipherSuite)
        {
        case CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
            return EncryptionAlgorithm._3DES_EDE_CBC;

        case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
            return EncryptionAlgorithm.AES_128_CBC;

        case CipherSuite.TLS_AES_128_CCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
            return EncryptionAlgorithm.AES_128_CCM;

        case CipherSuite.TLS_AES_128_CCM_8_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
            return EncryptionAlgorithm.AES_128_CCM_8;

        case CipherSuite.TLS_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
            return EncryptionAlgorithm.AES_128_GCM;

        case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
            return EncryptionAlgorithm.AES_256_CBC;

        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
            return EncryptionAlgorithm.AES_256_CCM;

        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
            return EncryptionAlgorithm.AES_256_CCM_8;

        case CipherSuite.TLS_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
            return EncryptionAlgorithm.AES_256_GCM;

        case CipherSuite.TLS_DH_anon_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256:
            return EncryptionAlgorithm.ARIA_128_CBC;

        case CipherSuite.TLS_DH_anon_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256:
            return EncryptionAlgorithm.ARIA_128_GCM;

        case CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384:
            return EncryptionAlgorithm.ARIA_256_CBC;

        case CipherSuite.TLS_DH_anon_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384:
            return EncryptionAlgorithm.ARIA_256_GCM;

        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256:
            return EncryptionAlgorithm.CAMELLIA_128_CBC;

        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
            return EncryptionAlgorithm.CAMELLIA_128_GCM;

        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
            return EncryptionAlgorithm.CAMELLIA_256_CBC;

        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
            return EncryptionAlgorithm.CAMELLIA_256_GCM;

        case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
            return EncryptionAlgorithm.CHACHA20_POLY1305;

        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA:
            return EncryptionAlgorithm.NULL;

        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256:
        case CipherSuite.TLS_PSK_WITH_NULL_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA256:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
            return EncryptionAlgorithm.NULL;

        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384:
            return EncryptionAlgorithm.NULL;

        case CipherSuite.TLS_DH_anon_WITH_SEED_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA:
            return EncryptionAlgorithm.SEED_CBC;

        default:
            return -1;
        }
    }

    public static int getEncryptionAlgorithmType(int encryptionAlgorithm)
    {
        switch (encryptionAlgorithm)
        {
        case EncryptionAlgorithm.AES_128_CCM:
        case EncryptionAlgorithm.AES_128_CCM_8:
        case EncryptionAlgorithm.AES_128_GCM:
        case EncryptionAlgorithm.AES_256_CCM:
        case EncryptionAlgorithm.AES_256_CCM_8:
        case EncryptionAlgorithm.AES_256_GCM:
        case EncryptionAlgorithm.ARIA_128_GCM:
        case EncryptionAlgorithm.ARIA_256_GCM:
        case EncryptionAlgorithm.CAMELLIA_128_GCM:
        case EncryptionAlgorithm.CAMELLIA_256_GCM:
        case EncryptionAlgorithm.CHACHA20_POLY1305:
            return CipherType.aead;

        case EncryptionAlgorithm.RC2_CBC_40:
        case EncryptionAlgorithm.IDEA_CBC:
        case EncryptionAlgorithm.DES40_CBC:
        case EncryptionAlgorithm.DES_CBC:
        case EncryptionAlgorithm._3DES_EDE_CBC:
        case EncryptionAlgorithm.AES_128_CBC:
        case EncryptionAlgorithm.AES_256_CBC:
        case EncryptionAlgorithm.ARIA_128_CBC:
        case EncryptionAlgorithm.ARIA_256_CBC:
        case EncryptionAlgorithm.CAMELLIA_128_CBC:
        case EncryptionAlgorithm.CAMELLIA_256_CBC:
        case EncryptionAlgorithm.SEED_CBC:
            return CipherType.block;

        case EncryptionAlgorithm.NULL:
        case EncryptionAlgorithm.RC4_40:
        case EncryptionAlgorithm.RC4_128:
            return CipherType.stream;

        default:
            return -1;
        }
    }

    public static int getKeyExchangeAlgorithm(int cipherSuite)
    {
        switch (cipherSuite)
        {
        case CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_SEED_CBC_SHA:
            return KeyExchangeAlgorithm.DH_anon;

        case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA:
            return KeyExchangeAlgorithm.DH_DSS;

        case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA:
            return KeyExchangeAlgorithm.DH_RSA;

        case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA:
            return KeyExchangeAlgorithm.DHE_DSS;

        case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
            return KeyExchangeAlgorithm.DHE_PSK;

        case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA:
            return KeyExchangeAlgorithm.DHE_RSA;

        case CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_NULL_SHA:
            return KeyExchangeAlgorithm.ECDH_anon;

        case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA:
            return KeyExchangeAlgorithm.ECDH_ECDSA;

        case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA:
            return KeyExchangeAlgorithm.ECDH_RSA;

        case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
            return KeyExchangeAlgorithm.ECDHE_ECDSA;

        case CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
            return KeyExchangeAlgorithm.ECDHE_PSK;

        case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
            return KeyExchangeAlgorithm.ECDHE_RSA;

        case CipherSuite.TLS_AES_128_CCM_8_SHA256:
        case CipherSuite.TLS_AES_128_CCM_SHA256:
        case CipherSuite.TLS_AES_128_GCM_SHA256:
        case CipherSuite.TLS_AES_256_GCM_SHA384:
        case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            return KeyExchangeAlgorithm.NULL;

        case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_PSK_WITH_NULL_SHA256:
        case CipherSuite.TLS_PSK_WITH_NULL_SHA384:
            return KeyExchangeAlgorithm.PSK;

        case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
        case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA:
            return KeyExchangeAlgorithm.RSA;

        case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384:
            return KeyExchangeAlgorithm.RSA_PSK;

        case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
            return KeyExchangeAlgorithm.SRP;

        case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
            return KeyExchangeAlgorithm.SRP_DSS;

        case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
            return KeyExchangeAlgorithm.SRP_RSA;

        default:
            return -1;
        }
    }

    public static Vector getKeyExchangeAlgorithms(int[] cipherSuites)
    {
        Vector result = new Vector();
        if (null != cipherSuites)
        {
            for (int i = 0; i < cipherSuites.length; ++i)
            {
                addToSet(result, getKeyExchangeAlgorithm(cipherSuites[i]));
            }
            result.removeElement(Integers.valueOf(-1));
        }
        return result;
    }

    public static int getMACAlgorithm(int cipherSuite)
    {
        switch (cipherSuite)
        {
        case CipherSuite.TLS_AES_128_CCM_SHA256:
        case CipherSuite.TLS_AES_128_CCM_8_SHA256:
        case CipherSuite.TLS_AES_128_GCM_SHA256:
        case CipherSuite.TLS_AES_256_GCM_SHA384:
        case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
            return MACAlgorithm._null;

        case CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_SEED_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
            return MACAlgorithm.hmac_sha1;

        case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_PSK_WITH_NULL_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
            return MACAlgorithm.hmac_sha256;

        case CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_RSA_WITH_ARIA_256_CBC_SHA384:
            return MACAlgorithm.hmac_sha384;

        default:
            return -1;
        }
    }

    public static ProtocolVersion getMinimumVersion(int cipherSuite)
    {
        switch (cipherSuite)
        {
        case CipherSuite.TLS_AES_128_CCM_SHA256:
        case CipherSuite.TLS_AES_128_CCM_8_SHA256:
        case CipherSuite.TLS_AES_128_GCM_SHA256:
        case CipherSuite.TLS_AES_256_GCM_SHA384:
        case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            return ProtocolVersion.TLSv13;

        case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
            return ProtocolVersion.TLSv12;

        default:
            return ProtocolVersion.SSLv3;
        }
    }

    public static Vector getNamedGroupRoles(int[] cipherSuites)
    {
        return getNamedGroupRoles(getKeyExchangeAlgorithms(cipherSuites));
    }

    public static Vector getNamedGroupRoles(Vector keyExchangeAlgorithms)
    {
        Vector result = new Vector();
        for (int i = 0; i < keyExchangeAlgorithms.size(); ++i)
        {
            int keyExchangeAlgorithm = ((Integer)keyExchangeAlgorithms.elementAt(i)).intValue();
            switch (keyExchangeAlgorithm)
            {
            case KeyExchangeAlgorithm.DH_anon:
            case KeyExchangeAlgorithm.DH_DSS:
            case KeyExchangeAlgorithm.DH_RSA:
            case KeyExchangeAlgorithm.DHE_DSS:
            case KeyExchangeAlgorithm.DHE_PSK:
            case KeyExchangeAlgorithm.DHE_RSA:
            {
                addToSet(result, NamedGroupRole.dh);
                break;
            }

            case KeyExchangeAlgorithm.ECDH_anon:
            case KeyExchangeAlgorithm.ECDH_RSA:
            case KeyExchangeAlgorithm.ECDHE_PSK:
            case KeyExchangeAlgorithm.ECDHE_RSA:
            {
                addToSet(result, NamedGroupRole.ecdh);
                break;
            }

            case KeyExchangeAlgorithm.ECDH_ECDSA:
            case KeyExchangeAlgorithm.ECDHE_ECDSA:
            {
                addToSet(result, NamedGroupRole.ecdh);
                addToSet(result, NamedGroupRole.ecdsa);
                break;
            }

            case KeyExchangeAlgorithm.NULL:
            {
                // TODO[tls13] We're conservatively adding both here, though maybe only one is needed
                addToSet(result, NamedGroupRole.dh);
                addToSet(result, NamedGroupRole.ecdh);
                break;
            }
            }
        }
        return result;
    }

    public static boolean isAEADCipherSuite(int cipherSuite) throws IOException
    {
        return CipherType.aead == getCipherType(cipherSuite);
    }

    public static boolean isBlockCipherSuite(int cipherSuite) throws IOException
    {
        return CipherType.block == getCipherType(cipherSuite);
    }

    public static boolean isStreamCipherSuite(int cipherSuite) throws IOException
    {
        return CipherType.stream == getCipherType(cipherSuite);
    }

    /**
     * @return Whether a server can select the specified cipher suite given the available signature
     *         algorithms for ServerKeyExchange.
     */
    public static boolean isValidCipherSuiteForSignatureAlgorithms(int cipherSuite, Vector sigAlgs)
    {
        final int keyExchangeAlgorithm = getKeyExchangeAlgorithm(cipherSuite);

        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        case KeyExchangeAlgorithm.NULL:
        case KeyExchangeAlgorithm.SRP_RSA:
        case KeyExchangeAlgorithm.SRP_DSS:
            break;

        default:
            return true;
        }

        int count = sigAlgs.size();
        for (int i = 0; i < count; ++i)
        {
            Short sigAlg = (Short)sigAlgs.elementAt(i);
            if (null != sigAlg)
            {
                short signatureAlgorithm = sigAlg.shortValue();

                if (isValidSignatureAlgorithmForServerKeyExchange(signatureAlgorithm, keyExchangeAlgorithm))
                {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @deprecated Use {@link #isValidVersionForCipherSuite(int, ProtocolVersion)} instead.
     */
    public static boolean isValidCipherSuiteForVersion(int cipherSuite, ProtocolVersion version)
    {
        return isValidVersionForCipherSuite(cipherSuite, version);
    }

    static boolean isValidCipherSuiteSelection(int[] offeredCipherSuites, int cipherSuite)
    {
        return null != offeredCipherSuites
            && Arrays.contains(offeredCipherSuites, cipherSuite)
            && CipherSuite.TLS_NULL_WITH_NULL_NULL != cipherSuite
            && !CipherSuite.isSCSV(cipherSuite);
    }

    static boolean isValidKeyShareSelection(ProtocolVersion negotiatedVersion, int[] clientSupportedGroups,
        Hashtable clientAgreements, int keyShareGroup)
    {
        return null != clientSupportedGroups
            && Arrays.contains(clientSupportedGroups, keyShareGroup)
            && !clientAgreements.containsKey(Integers.valueOf(keyShareGroup))
            && NamedGroup.canBeNegotiated(keyShareGroup, negotiatedVersion);
    }

    static boolean isValidSignatureAlgorithmForCertificateVerify(short signatureAlgorithm, short[] clientCertificateTypes)
    {
        short clientCertificateType = SignatureAlgorithm.getClientCertificateType(signatureAlgorithm);

        return clientCertificateType >= 0 &&  Arrays.contains(clientCertificateTypes, clientCertificateType);
    }

    static boolean isValidSignatureAlgorithmForServerKeyExchange(short signatureAlgorithm, int keyExchangeAlgorithm)
    {
        // TODO [tls13]

        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        case KeyExchangeAlgorithm.SRP_RSA:
            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.rsa:
            case SignatureAlgorithm.rsa_pss_rsae_sha256:
            case SignatureAlgorithm.rsa_pss_rsae_sha384:
            case SignatureAlgorithm.rsa_pss_rsae_sha512:
            case SignatureAlgorithm.rsa_pss_pss_sha256:
            case SignatureAlgorithm.rsa_pss_pss_sha384:
            case SignatureAlgorithm.rsa_pss_pss_sha512:
                return true;
            default:
                return false;
            }

        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.SRP_DSS:
            return SignatureAlgorithm.dsa == signatureAlgorithm;

        case KeyExchangeAlgorithm.ECDHE_ECDSA:
            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.ecdsa:
            case SignatureAlgorithm.ed25519:
            case SignatureAlgorithm.ed448:
                return true;
            default:
                return false;
            }

        case KeyExchangeAlgorithm.NULL:
            return SignatureAlgorithm.anonymous != signatureAlgorithm;

        default:
            return false;
        }
    }

    public static boolean isValidSignatureSchemeForServerKeyExchange(int signatureScheme, int keyExchangeAlgorithm)
    {
        short signatureAlgorithm = SignatureScheme.getSignatureAlgorithm(signatureScheme);

        return isValidSignatureAlgorithmForServerKeyExchange(signatureAlgorithm, keyExchangeAlgorithm);
    }

    public static boolean isValidVersionForCipherSuite(int cipherSuite, ProtocolVersion version)
    {
        version = version.getEquivalentTLSVersion();

        ProtocolVersion minimumVersion = getMinimumVersion(cipherSuite);
        if (minimumVersion == version)
        {
            return true;
        }
        if (!minimumVersion.isEarlierVersionOf(version))
        {
            return false;
        }
        return ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(minimumVersion)
            || ProtocolVersion.TLSv13.isLaterVersionOf(version);
    }

    public static SignatureAndHashAlgorithm chooseSignatureAndHashAlgorithm(TlsContext context, Vector sigHashAlgs, short signatureAlgorithm)
        throws IOException
    {
        if (!isTLSv12(context))
        {
            return null;
        }

        if (sigHashAlgs == null)
        {
            /*
             * TODO[tls13] RFC 8446 4.2.3 Clients which desire the server to authenticate itself via
             * a certificate MUST send the "signature_algorithms" extension.
             */

            sigHashAlgs = getDefaultSignatureAlgorithms(signatureAlgorithm);
        }

        SignatureAndHashAlgorithm result = null;
        for (int i = 0; i < sigHashAlgs.size(); ++i)
        {
            SignatureAndHashAlgorithm sigHashAlg = (SignatureAndHashAlgorithm)sigHashAlgs.elementAt(i);
            if (sigHashAlg.getSignature() == signatureAlgorithm)
            {
                short hash = sigHashAlg.getHash();
                if (hash < MINIMUM_HASH_STRICT)
                {
                    continue;
                }
                if (result == null)
                {
                    result = sigHashAlg;
                    continue;
                }

                short current = result.getHash();
                if (current < MINIMUM_HASH_PREFERRED)
                {
                    if (hash > current)
                    {
                        result = sigHashAlg;
                    }
                }
                else if (hash >= MINIMUM_HASH_PREFERRED)
                {
                    if (hash < current)
                    {
                        result = sigHashAlg;
                    }
                }
            }
        }
        if (result == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        return result;
    }

    public static Vector getUsableSignatureAlgorithms(Vector sigHashAlgs)
    {
        if (sigHashAlgs == null)
        {
            Vector v = new Vector(3);
            v.addElement(Shorts.valueOf(SignatureAlgorithm.rsa));
            v.addElement(Shorts.valueOf(SignatureAlgorithm.dsa));
            v.addElement(Shorts.valueOf(SignatureAlgorithm.ecdsa));
            return v;
        }

        Vector v = new Vector();
        for (int i = 0; i < sigHashAlgs.size(); ++i)
        {
            SignatureAndHashAlgorithm sigHashAlg = (SignatureAndHashAlgorithm)sigHashAlgs.elementAt(i);
            if (sigHashAlg.getHash() >= MINIMUM_HASH_STRICT)
            {
                Short sigAlg = Shorts.valueOf(sigHashAlg.getSignature());
                if (!v.contains(sigAlg))
                {
                    // TODO Check for crypto support before choosing (or pass in cached list?)
                    v.addElement(sigAlg);
                }
            }
        }
        return v;
    }

    public static int[] getCommonCipherSuites(int[] peerCipherSuites, int[] localCipherSuites, boolean useLocalOrder)
    {
        int[] ordered = peerCipherSuites, unordered = localCipherSuites;
        if (useLocalOrder)
        {
            ordered = localCipherSuites;
            unordered = peerCipherSuites;
        }

        int count = 0, limit = Math.min(ordered.length, unordered.length);
        int[] candidates = new int[limit];
        for (int i = 0; i < ordered.length; ++i)
        {
            int candidate = ordered[i];
            if (!contains(candidates, 0, count, candidate)
                && Arrays.contains(unordered, candidate))
            {
                candidates[count++] = candidate;
            }
        }

        if (count < limit)
        {
            candidates = Arrays.copyOf(candidates, count);
        }

        return candidates;
    }

    public static int[] getSupportedCipherSuites(TlsCrypto crypto, int[] suites)
    {
        return getSupportedCipherSuites(crypto, suites, suites.length);
    }

    public static int[] getSupportedCipherSuites(TlsCrypto crypto, int[] suites, int suitesCount)
    {
        int[] supported = new int[suitesCount];
        int count = 0;

        for (int i = 0; i < suitesCount; ++i)
        {
            int suite = suites[i];
            if (isSupportedCipherSuite(crypto, suite))
            {
                supported[count++] = suite;
            }
        }

        if (count < suitesCount)
        {
            supported = Arrays.copyOf(supported, count);
        }

        return supported;
    }

    public static boolean isSupportedCipherSuite(TlsCrypto crypto, int cipherSuite)
    {
        return isSupportedKeyExchange(crypto, getKeyExchangeAlgorithm(cipherSuite))
            && crypto.hasEncryptionAlgorithm(getEncryptionAlgorithm(cipherSuite))
            && crypto.hasMacAlgorithm(getMACAlgorithm(cipherSuite));
    }

    public static boolean isSupportedKeyExchange(TlsCrypto crypto, int keyExchangeAlgorithm)
    {
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_anon:
        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_RSA:
        case KeyExchangeAlgorithm.DHE_PSK:
            return crypto.hasDHAgreement();

        case KeyExchangeAlgorithm.DHE_DSS:
            return crypto.hasDHAgreement()
                && crypto.hasSignatureAlgorithm(SignatureAlgorithm.dsa);

        case KeyExchangeAlgorithm.DHE_RSA:
            return crypto.hasDHAgreement()
                && hasAnyRSASigAlgs(crypto);

        case KeyExchangeAlgorithm.ECDH_anon:
        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
        case KeyExchangeAlgorithm.ECDHE_PSK:
            return crypto.hasECDHAgreement();

        case KeyExchangeAlgorithm.ECDHE_ECDSA:
            return crypto.hasECDHAgreement()
                && (crypto.hasSignatureAlgorithm(SignatureAlgorithm.ecdsa)
                    || crypto.hasSignatureAlgorithm(SignatureAlgorithm.ed25519)
                    || crypto.hasSignatureAlgorithm(SignatureAlgorithm.ed448));

        case KeyExchangeAlgorithm.ECDHE_RSA:
            return crypto.hasECDHAgreement()
                && hasAnyRSASigAlgs(crypto);

        case KeyExchangeAlgorithm.NULL:
        case KeyExchangeAlgorithm.PSK:
            return true;

        case KeyExchangeAlgorithm.RSA:
        case KeyExchangeAlgorithm.RSA_PSK:
            return crypto.hasRSAEncryption();

        case KeyExchangeAlgorithm.SRP:
            return crypto.hasSRPAuthentication();

        case KeyExchangeAlgorithm.SRP_DSS:
            return crypto.hasSRPAuthentication()
                && crypto.hasSignatureAlgorithm(SignatureAlgorithm.dsa);

        case KeyExchangeAlgorithm.SRP_RSA:
            return crypto.hasSRPAuthentication()
                && hasAnyRSASigAlgs(crypto);

        default:
            return false;
        }
    }

    static boolean hasAnyRSASigAlgs(TlsCrypto crypto)
    {
        return crypto.hasSignatureAlgorithm(SignatureAlgorithm.rsa)
            || crypto.hasSignatureAlgorithm(SignatureAlgorithm.rsa_pss_rsae_sha256)
            || crypto.hasSignatureAlgorithm(SignatureAlgorithm.rsa_pss_rsae_sha384)
            || crypto.hasSignatureAlgorithm(SignatureAlgorithm.rsa_pss_rsae_sha512)
            || crypto.hasSignatureAlgorithm(SignatureAlgorithm.rsa_pss_pss_sha256)
            || crypto.hasSignatureAlgorithm(SignatureAlgorithm.rsa_pss_pss_sha384)
            || crypto.hasSignatureAlgorithm(SignatureAlgorithm.rsa_pss_pss_sha512);
    }

    static byte[] getCurrentPRFHash(TlsHandshakeHash handshakeHash)
    {
        return handshakeHash.forkPRFHash().calculateHash();
    }

    static void sealHandshakeHash(TlsContext context, TlsHandshakeHash handshakeHash, boolean forceBuffering)
    {
        if (forceBuffering || !context.getCrypto().hasAllRawSignatureAlgorithms())
        {
            handshakeHash.forceBuffering();
        }

        handshakeHash.sealHashAlgorithms();
    }

    private static TlsKeyExchange createKeyExchangeClient(TlsClient client, int keyExchange) throws IOException
    {
        TlsKeyExchangeFactory factory = client.getKeyExchangeFactory();

        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.DH_anon:
            return factory.createDHanonKeyExchangeClient(keyExchange, client.getDHGroupVerifier());

        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_RSA:
            return factory.createDHKeyExchange(keyExchange);

        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
            return factory.createDHEKeyExchangeClient(keyExchange, client.getDHGroupVerifier());

        case KeyExchangeAlgorithm.ECDH_anon:
            return factory.createECDHanonKeyExchangeClient(keyExchange);

        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
            return factory.createECDHKeyExchange(keyExchange);

        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
            return factory.createECDHEKeyExchangeClient(keyExchange);

        case KeyExchangeAlgorithm.RSA:
            return factory.createRSAKeyExchange(keyExchange);

        case KeyExchangeAlgorithm.DHE_PSK:
            return factory.createPSKKeyExchangeClient(keyExchange, client.getPSKIdentity(),
                client.getDHGroupVerifier());

        case KeyExchangeAlgorithm.ECDHE_PSK:
        case KeyExchangeAlgorithm.PSK:
        case KeyExchangeAlgorithm.RSA_PSK:
            return factory.createPSKKeyExchangeClient(keyExchange, client.getPSKIdentity(), null);

        case KeyExchangeAlgorithm.SRP:
        case KeyExchangeAlgorithm.SRP_DSS:
        case KeyExchangeAlgorithm.SRP_RSA:
            return factory.createSRPKeyExchangeClient(keyExchange, client.getSRPIdentity(),
                client.getSRPConfigVerifier());

        default:
            /*
             * Note: internal error here; the TlsProtocol implementation verifies that the
             * server-selected cipher suite was in the list of client-offered cipher suites, so if
             * we now can't produce an implementation, we shouldn't have offered it!
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    private static TlsKeyExchange createKeyExchangeServer(TlsServer server, int keyExchange) throws IOException
    {
        TlsKeyExchangeFactory factory = server.getKeyExchangeFactory();

        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.DH_anon:
            return factory.createDHanonKeyExchangeServer(keyExchange, server.getDHConfig());

        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_RSA:
            return factory.createDHKeyExchange(keyExchange);

        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
            return factory.createDHEKeyExchangeServer(keyExchange, server.getDHConfig());

        case KeyExchangeAlgorithm.ECDH_anon:
            return factory.createECDHanonKeyExchangeServer(keyExchange, server.getECDHConfig());

        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
            return factory.createECDHKeyExchange(keyExchange);

        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
            return factory.createECDHEKeyExchangeServer(keyExchange, server.getECDHConfig());

        case KeyExchangeAlgorithm.RSA:
            return factory.createRSAKeyExchange(keyExchange);

        case KeyExchangeAlgorithm.DHE_PSK:
            return factory.createPSKKeyExchangeServer(keyExchange, server.getPSKIdentityManager(), server.getDHConfig(),
                null);

        case KeyExchangeAlgorithm.ECDHE_PSK:
            return factory.createPSKKeyExchangeServer(keyExchange, server.getPSKIdentityManager(), null, server.getECDHConfig());

        case KeyExchangeAlgorithm.PSK:
        case KeyExchangeAlgorithm.RSA_PSK:
            return factory.createPSKKeyExchangeServer(keyExchange, server.getPSKIdentityManager(), null, null);

        case KeyExchangeAlgorithm.SRP:
        case KeyExchangeAlgorithm.SRP_DSS:
        case KeyExchangeAlgorithm.SRP_RSA:
            return factory.createSRPKeyExchangeServer(keyExchange, server.getSRPLoginParameters());

        default:
            /*
             * Note: internal error here; the TlsProtocol implementation verifies that the
             * server-selected cipher suite was in the list of client-offered cipher suites, so if
             * we now can't produce an implementation, we shouldn't have offered it!
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    static TlsKeyExchange initKeyExchangeClient(TlsClientContext clientContext, TlsClient client) throws IOException
    {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        TlsKeyExchange keyExchange = createKeyExchangeClient(client, securityParameters.getKeyExchangeAlgorithm());
        keyExchange.init(clientContext);
        return keyExchange;
    }

    static TlsKeyExchange initKeyExchangeServer(TlsServerContext serverContext, TlsServer server) throws IOException
    {
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();
        TlsKeyExchange keyExchange = createKeyExchangeServer(server, securityParameters.getKeyExchangeAlgorithm());
        keyExchange.init(serverContext);
        return keyExchange;
    }

    static TlsCipher initCipher(TlsContext context) throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        int cipherSuite = securityParameters.getCipherSuite();
        int encryptionAlgorithm = getEncryptionAlgorithm(cipherSuite);
        int macAlgorithm = getMACAlgorithm(cipherSuite);

        if (encryptionAlgorithm < 0 || macAlgorithm < 0)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return context.getCrypto().createCipher(new TlsCryptoParameters(context), encryptionAlgorithm, macAlgorithm);
    }

    /**
     * Check the signature algorithm for certificates in the peer's CertPath as specified in RFC
     * 5246 7.4.2, 7.4.4, 7.4.6 and similar rules for earlier TLS versions. The supplied CertPath
     * should include the trust anchor (its signature algorithm isn't checked, but in the general
     * case checking a certificate requires the issuer certificate).
     *
     * @throws IOException
     *             if any certificate in the CertPath (excepting the trust anchor) has a signature
     *             algorithm that is not one of the locally supported signature algorithms.
     */
    public static void checkPeerSigAlgs(TlsContext context, TlsCertificate[] peerCertPath) throws IOException
    {
        if (context.isServer())
        {
            checkSigAlgOfClientCerts(context, peerCertPath);
        }
        else
        {
            checkSigAlgOfServerCerts(context, peerCertPath);
        }
    }

    private static void checkSigAlgOfClientCerts(TlsContext context, TlsCertificate[] clientCertPath) throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        short[] clientCertTypes = securityParameters.getClientCertTypes();
        Vector serverSigAlgsCert = securityParameters.getServerSigAlgsCert();

        int trustAnchorPos = clientCertPath.length - 1;
        for (int i = 0; i < trustAnchorPos; ++i)
        {
            TlsCertificate subjectCert = clientCertPath[i];
            TlsCertificate issuerCert = clientCertPath[i + 1];

            SignatureAndHashAlgorithm sigAndHashAlg = getCertSigAndHashAlg(subjectCert, issuerCert);

            boolean valid = false;
            if (null == sigAndHashAlg)
            {
                // We don't recognize the 'signatureAlgorithm' of the certificate
            }
            else if (null == serverSigAlgsCert)
            {
                // TODO Review this (legacy) logic with RFC 4346 (7.4?.2?)
                if (null != clientCertTypes)
                {
                    for (int j = 0; j < clientCertTypes.length; ++j)
                    {
                        short signatureAlgorithm = getLegacySignatureAlgorithmClientCert(clientCertTypes[j]);
                        if (sigAndHashAlg.getSignature() == signatureAlgorithm)
                        {
                            valid = true;
                            break;
                        }
                    }
                }
            }
            else
            {
                /*
                 * RFC 5246 7.4.4 Any certificates provided by the client MUST be signed using a
                 * hash/signature algorithm pair found in supported_signature_algorithms.
                 */
                valid = containsSignatureAlgorithm(serverSigAlgsCert, sigAndHashAlg);
            }

            if (!valid)
            {
                throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }
        }
    }

    private static void checkSigAlgOfServerCerts(TlsContext context, TlsCertificate[] serverCertPath) throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        Vector clientSigAlgsCert = securityParameters.getClientSigAlgsCert();
        Vector clientSigAlgs = securityParameters.getClientSigAlgs();

        /*
         * NOTE: For TLS 1.2, we'll check 'signature_algorithms' too (if it's distinct), since
         * there's no way of knowing whether the server understood 'signature_algorithms_cert'.
         */
        if (clientSigAlgs == clientSigAlgsCert || isTLSv13(securityParameters.getNegotiatedVersion()))
        {
            clientSigAlgs = null;
        }

        int trustAnchorPos = serverCertPath.length - 1;
        for (int i = 0; i < trustAnchorPos; ++i)
        {
            TlsCertificate subjectCert = serverCertPath[i];
            TlsCertificate issuerCert = serverCertPath[i + 1];

            SignatureAndHashAlgorithm sigAndHashAlg = getCertSigAndHashAlg(subjectCert, issuerCert);

            boolean valid = false;
            if (null == sigAndHashAlg)
            {
                // We don't recognize the 'signatureAlgorithm' of the certificate
            }
            else if (null == clientSigAlgsCert)
            {
                /*
                 * RFC 4346 7.4.2. Unless otherwise specified, the signing algorithm for the
                 * certificate MUST be the same as the algorithm for the certificate key.
                 */
                short signatureAlgorithm = getLegacySignatureAlgorithmServerCert(
                    securityParameters.getKeyExchangeAlgorithm());

                valid = (signatureAlgorithm == sigAndHashAlg.getSignature()); 
            }
            else
            {
                /*
                 * RFC 5246 7.4.2. If the client provided a "signature_algorithms" extension, then
                 * all certificates provided by the server MUST be signed by a hash/signature algorithm
                 * pair that appears in that extension.
                 */
                valid = containsSignatureAlgorithm(clientSigAlgsCert, sigAndHashAlg)
                    || (null != clientSigAlgs && containsSignatureAlgorithm(clientSigAlgs, sigAndHashAlg));
            }

            if (!valid)
            {
                throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }
        }
    }

    static void checkTlsFeatures(Certificate serverCertificate, Hashtable clientExtensions, Hashtable serverExtensions) throws IOException
    {
        /*
         * RFC 7633 4.3.3. A client MUST treat a certificate with a TLS feature extension as an
         * invalid certificate if the features offered by the server do not contain all features
         * present in both the client's ClientHello message and the TLS feature extension.
         */
        byte[] tlsFeatures = serverCertificate.getCertificateAt(0).getExtension(TlsObjectIdentifiers.id_pe_tlsfeature);
        if (tlsFeatures != null)
        {
            Enumeration tlsExtensions = ((ASN1Sequence)readDERObject(tlsFeatures)).getObjects();
            while (tlsExtensions.hasMoreElements())
            {
                BigInteger tlsExtension = ((ASN1Integer)tlsExtensions.nextElement()).getPositiveValue();
                if (tlsExtension.bitLength() <= 16)
                {
                    Integer extensionType = Integers.valueOf(tlsExtension.intValue());
                    if (clientExtensions.containsKey(extensionType) && !serverExtensions.containsKey(extensionType))
                    {
                        throw new TlsFatalAlert(AlertDescription.certificate_unknown);
                    }
                }
            }
        }
    }

    static void processClientCertificate(TlsServerContext serverContext, Certificate clientCertificate,
        TlsKeyExchange keyExchange, TlsServer server) throws IOException
    {
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();
        if (null != securityParameters.getPeerCertificate())
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        boolean isTLSv13 = TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion());
        if (isTLSv13)
        {
            // 'keyExchange' not used
        }
        else if (clientCertificate.isEmpty())
        {
            /*
             * NOTE: We tolerate SSLv3 clients sending an empty chain, although "If no suitable
             * certificate is available, the client should send a no_certificate alert instead".
             */

            keyExchange.skipClientCredentials();
        }
        else
        {
            keyExchange.processClientCertificate(clientCertificate);
        }

        securityParameters.peerCertificate = clientCertificate;

        /*
         * RFC 5246 7.4.6. If the client does not send any certificates, the server MAY at its
         * discretion either continue the handshake without client authentication, or respond with a
         * fatal handshake_failure alert. Also, if some aspect of the certificate chain was
         * unacceptable (e.g., it was not signed by a known, trusted CA), the server MAY at its
         * discretion either continue the handshake (considering the client unauthenticated) or send
         * a fatal alert.
         */
        server.notifyClientCertificate(clientCertificate);
    }

    static void processServerCertificate(TlsClientContext clientContext,
        CertificateStatus serverCertificateStatus, TlsKeyExchange keyExchange, TlsAuthentication clientAuthentication,
        Hashtable clientExtensions, Hashtable serverExtensions) throws IOException
    {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        boolean isTLSv13 = TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion());

        if (null == clientAuthentication)
        {
            if (isTLSv13)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            // There was no server certificate message; check it's OK
            keyExchange.skipServerCredentials();
            securityParameters.tlsServerEndPoint = EMPTY_BYTES;
            return;
        }

        Certificate serverCertificate = securityParameters.getPeerCertificate();

        checkTlsFeatures(serverCertificate, clientExtensions, serverExtensions);

        if (!isTLSv13)
        {
            keyExchange.processServerCertificate(serverCertificate);
        }

        clientAuthentication.notifyServerCertificate(new TlsServerCertificateImpl(serverCertificate, serverCertificateStatus));
    }

    static SignatureAndHashAlgorithm getCertSigAndHashAlg(TlsCertificate subjectCert, TlsCertificate issuerCert)
        throws IOException
    {
        String sigAlgOID = subjectCert.getSigAlgOID();

        if (null != sigAlgOID)
        {
            if (!PKCSObjectIdentifiers.id_RSASSA_PSS.getId().equals(sigAlgOID))
            {
                return (SignatureAndHashAlgorithm)CERT_SIG_ALG_OIDS.get(sigAlgOID);
            }

            RSASSAPSSparams pssParams = RSASSAPSSparams.getInstance(subjectCert.getSigAlgParams());
            if (null != pssParams)
            {
                ASN1ObjectIdentifier hashOID = pssParams.getHashAlgorithm().getAlgorithm();
                if (NISTObjectIdentifiers.id_sha256.equals(hashOID))
                {
                    if (issuerCert.supportsSignatureAlgorithmCA(SignatureAlgorithm.rsa_pss_pss_sha256))
                    {
                        return SignatureAndHashAlgorithm.rsa_pss_pss_sha256;
                    }
                    else if (issuerCert.supportsSignatureAlgorithmCA(SignatureAlgorithm.rsa_pss_rsae_sha256))
                    {
                        return SignatureAndHashAlgorithm.rsa_pss_rsae_sha256;
                    }
                }
                else if (NISTObjectIdentifiers.id_sha384.equals(hashOID))
                {
                    if (issuerCert.supportsSignatureAlgorithmCA(SignatureAlgorithm.rsa_pss_pss_sha384))
                    {
                        return SignatureAndHashAlgorithm.rsa_pss_pss_sha384;
                    }
                    else if (issuerCert.supportsSignatureAlgorithmCA(SignatureAlgorithm.rsa_pss_rsae_sha384))
                    {
                        return SignatureAndHashAlgorithm.rsa_pss_rsae_sha384;
                    }
                }
                else if (NISTObjectIdentifiers.id_sha512.equals(hashOID))
                {
                    if (issuerCert.supportsSignatureAlgorithmCA(SignatureAlgorithm.rsa_pss_pss_sha512))
                    {
                        return SignatureAndHashAlgorithm.rsa_pss_pss_sha512;
                    }
                    else if (issuerCert.supportsSignatureAlgorithmCA(SignatureAlgorithm.rsa_pss_rsae_sha512))
                    {
                        return SignatureAndHashAlgorithm.rsa_pss_rsae_sha512;
                    }
                }
            }
        }

        return null;
    }

    static CertificateRequest validateCertificateRequest(CertificateRequest certificateRequest, TlsKeyExchange keyExchange)
        throws IOException
    {
        short[] validClientCertificateTypes = keyExchange.getClientCertificateTypes();
        if (validClientCertificateTypes == null || validClientCertificateTypes.length < 1)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        certificateRequest = normalizeCertificateRequest(certificateRequest, validClientCertificateTypes);
        if (certificateRequest == null)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return certificateRequest;
    }

    static CertificateRequest normalizeCertificateRequest(CertificateRequest certificateRequest, short[] validClientCertificateTypes)
    {
        if (containsAll(validClientCertificateTypes, certificateRequest.getCertificateTypes()))
        {
            return certificateRequest;
        }

        short[] retained = retainAll(certificateRequest.getCertificateTypes(), validClientCertificateTypes);
        if (retained.length < 1)
        {
            return null;
        }

        // TODO Filter for unique sigAlgs/CAs only
        return new CertificateRequest(retained, certificateRequest.getSupportedSignatureAlgorithms(),
            certificateRequest.getCertificateAuthorities());
    }

    static boolean contains(int[] buf, int off, int len, int value)
    {
        for (int i = 0; i < len; ++i)
        {
            if (value == buf[off + i])
            {
                return true;
            }
        }
        return false;
    }

    static boolean containsAll(short[] container, short[] elements)
    {
        for (int i = 0; i < elements.length; ++i)
        {
            if (!Arrays.contains(container, elements[i]))
            {
                return false;
            }
        }
        return true;
    }

    static short[] retainAll(short[] retainer, short[] elements)
    {
        short[] retained = new short[Math.min(retainer.length, elements.length)];

        int count = 0;
        for (int i = 0; i < elements.length; ++i)
        {
            if (Arrays.contains(retainer, elements[i]))
            {
                retained[count++] = elements[i];
            }
        }

        return truncate(retained, count);
    }

    static short[] truncate(short[] a, int n)
    {
        if (n < a.length)
        {
            return a;
        }

        short[] t = new short[n];
        System.arraycopy(a, 0,  t, 0, n);
        return t;
    }

    static TlsCredentialedAgreement requireAgreementCredentials(TlsCredentials credentials)
        throws IOException
    {
        if (!(credentials instanceof TlsCredentialedAgreement))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return (TlsCredentialedAgreement)credentials;
    }

    static TlsCredentialedDecryptor requireDecryptorCredentials(TlsCredentials credentials)
        throws IOException
    {
        if (!(credentials instanceof TlsCredentialedDecryptor))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return (TlsCredentialedDecryptor)credentials;
    }

    static TlsCredentialedSigner requireSignerCredentials(TlsCredentials credentials)
        throws IOException
    {
        if (!(credentials instanceof TlsCredentialedSigner))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return (TlsCredentialedSigner)credentials;
    }

    private static void checkDowngradeMarker(byte[] randomBlock, byte[] downgradeMarker) throws IOException
    {
        int len = downgradeMarker.length;
        if (constantTimeAreEqual(len, downgradeMarker, 0, randomBlock, randomBlock.length - len))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
    }

    static void checkDowngradeMarker(ProtocolVersion version, byte[] randomBlock) throws IOException
    {
        version = version.getEquivalentTLSVersion();

        if (version.isEqualOrEarlierVersionOf(ProtocolVersion.TLSv11))
        {
            checkDowngradeMarker(randomBlock, DOWNGRADE_TLS11);
        }
        if (version.isEqualOrEarlierVersionOf(ProtocolVersion.TLSv12))
        {
            checkDowngradeMarker(randomBlock, DOWNGRADE_TLS12);
        }
    }

    static void writeDowngradeMarker(ProtocolVersion version, byte[] randomBlock) throws IOException
    {
        version = version.getEquivalentTLSVersion();

        byte[] marker;
        if (ProtocolVersion.TLSv12 == version)
        {
            marker = DOWNGRADE_TLS12;
        }
        else if (version.isEqualOrEarlierVersionOf(ProtocolVersion.TLSv11))
        {
            marker = DOWNGRADE_TLS11;
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        System.arraycopy(marker, 0, randomBlock, randomBlock.length - marker.length, marker.length);
    }

    static TlsAuthentication receiveServerCertificate(TlsClientContext clientContext, TlsClient client,
        ByteArrayInputStream buf) throws IOException
    {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        if (null != securityParameters.getPeerCertificate())
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        ByteArrayOutputStream endPointHash = new ByteArrayOutputStream();

        Certificate serverCertificate = Certificate.parse(clientContext, buf, endPointHash);

        TlsProtocol.assertEmpty(buf);

        if (serverCertificate.isEmpty())
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        securityParameters.peerCertificate = serverCertificate;
        securityParameters.tlsServerEndPoint = endPointHash.toByteArray();

        TlsAuthentication authentication = client.getAuthentication();
        if (null == authentication)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return authentication;
    }

    static TlsAuthentication receive13ServerCertificate(TlsClientContext clientContext, TlsClient client,
        ByteArrayInputStream buf) throws IOException
    {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        if (null != securityParameters.getPeerCertificate())
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        Certificate serverCertificate = Certificate.parse(clientContext, buf, null);

        TlsProtocol.assertEmpty(buf);

        if (serverCertificate.getCertificateRequestContext().length > 0)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        if (serverCertificate.isEmpty())
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        securityParameters.peerCertificate = serverCertificate;
        securityParameters.tlsServerEndPoint = null;

        TlsAuthentication authentication = client.getAuthentication();
        if (null == authentication)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return authentication;
    }

    public static boolean containsNonAscii(byte[] bs)
    {
        for (int i = 0; i < bs.length; ++i)
        {
            int c = bs[i] & 0xFF;;
            if (c >= 0x80)
            {
                return true;
            }
        }
        return false;
    }

    public static boolean containsNonAscii(String s)
    {
        for (int i = 0; i < s.length(); ++i)
        {
            int c = s.charAt(i);
            if (c >= 0x80)
            {
                return true;
            }
        }
        return false;
    }

    static Hashtable addEarlyKeySharesToClientHello(TlsClientContext clientContext, TlsClient client,
        Hashtable clientExtensions) throws IOException
    {
        /*
         * RFC 8446 9.2. If containing a "supported_groups" extension, it MUST also contain a
         * "key_share" extension, and vice versa. An empty KeyShare.client_shares vector is
         * permitted.
         */
        if (!isTLSv13(clientContext.getClientVersion())
            || !clientExtensions.containsKey(TlsExtensionsUtils.EXT_supported_groups))
        {
            return null;
        }

        int[] supportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(clientExtensions);
        Vector keyShareGroups = client.getEarlyKeyShareGroups();
        Hashtable clientAgreements = new Hashtable(3);
        Vector clientShares = new Vector(2);

        collectKeyShares(clientContext.getCrypto(), supportedGroups, keyShareGroups, clientAgreements, clientShares);

        TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, clientShares);

        return clientAgreements;
    }

    static Hashtable addKeyShareToClientHelloRetry(TlsClientContext clientContext, Hashtable clientExtensions,
        int keyShareGroup) throws IOException
    {
        int[] supportedGroups = new int[]{ keyShareGroup };
        Vector keyShareGroups = vectorOfOne(Integers.valueOf(keyShareGroup));
        Hashtable clientAgreements = new Hashtable(1, 1.0f);
        Vector clientShares = new Vector(1);

        collectKeyShares(clientContext.getCrypto(), supportedGroups, keyShareGroups, clientAgreements, clientShares);

        TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, clientShares);

        if (clientAgreements.isEmpty() || clientShares.isEmpty())
        {
            // NOTE: Probable cause is declaring an unsupported NamedGroup in supported_groups extension 
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return clientAgreements;
    }

    private static void collectKeyShares(TlsCrypto crypto, int[] supportedGroups, Vector keyShareGroups,
        Hashtable clientAgreements, Vector clientShares) throws IOException
    {
        if (null == supportedGroups || supportedGroups.length < 1)
        {
            return;
        }
        if (null == keyShareGroups || keyShareGroups.isEmpty())
        {
            return;
        }

        for (int i = 0; i < supportedGroups.length; ++i)
        {
            int supportedGroup = supportedGroups[i];
            Integer supportedGroupElement = Integers.valueOf(supportedGroup);

            if (!keyShareGroups.contains(supportedGroupElement)
                || clientAgreements.containsKey(supportedGroupElement)
                || !crypto.hasNamedGroup(supportedGroup))
            {
                continue;
            }

            TlsAgreement agreement = null;
            if (NamedGroup.refersToASpecificCurve(supportedGroup))
            {
                if (crypto.hasECDHAgreement())
                {
                    agreement = crypto.createECDomain(new TlsECConfig(supportedGroup)).createECDH();
                }
            }
            else if (NamedGroup.refersToASpecificFiniteField(supportedGroup))
            {
                if (crypto.hasDHAgreement())
                {
                    agreement = crypto.createDHDomain(new TlsDHConfig(supportedGroup, true)).createDH();
                }
            }

            if (null != agreement)
            {
                byte[] key_exchange = agreement.generateEphemeral();
                KeyShareEntry clientShare = new KeyShareEntry(supportedGroup, key_exchange);

                clientShares.addElement(clientShare);
                clientAgreements.put(supportedGroupElement, agreement);
            }
        }
    }

    static KeyShareEntry selectKeyShare(Vector clientShares, int keyShareGroup)
    {
        if (null != clientShares && 1 == clientShares.size())
        {
            KeyShareEntry clientShare = (KeyShareEntry)clientShares.elementAt(0);
            if (null != clientShare && clientShare.getNamedGroup() == keyShareGroup)
            {
                return clientShare;
            }
        }
        return null;
    }

    static KeyShareEntry selectKeyShare(TlsCrypto crypto, ProtocolVersion negotiatedVersion, Vector clientShares,
        int[] clientSupportedGroups, int[] serverSupportedGroups)
    {
        if (null != clientShares && !isNullOrEmpty(clientSupportedGroups) && !isNullOrEmpty(serverSupportedGroups))
        {
            for (int i = 0; i < clientShares.size(); ++i)
            {
                KeyShareEntry clientShare = (KeyShareEntry)clientShares.elementAt(i);

                int group = clientShare.getNamedGroup();

                if (!NamedGroup.canBeNegotiated(group, negotiatedVersion))
                {
                    continue;
                }

                if (!Arrays.contains(serverSupportedGroups, group) ||
                    !Arrays.contains(clientSupportedGroups, group))
                {
                    continue;
                }

                if (!crypto.hasNamedGroup(group))
                {
                    continue;
                }

                if ((NamedGroup.refersToASpecificCurve(group) && !crypto.hasECDHAgreement()) ||
                    (NamedGroup.refersToASpecificFiniteField(group) && !crypto.hasDHAgreement())) 
                {
                    continue;
                }

                return clientShare;
            }
        }
        return null;
    }

    static int selectKeyShareGroup(TlsCrypto crypto, ProtocolVersion negotiatedVersion,
        int[] clientSupportedGroups, int[] serverSupportedGroups)
    {
        if (!isNullOrEmpty(clientSupportedGroups) && !isNullOrEmpty(serverSupportedGroups))
        {
            for (int i = 0; i < clientSupportedGroups.length; ++i)
            {
                int group = clientSupportedGroups[i];

                if (!NamedGroup.canBeNegotiated(group, negotiatedVersion))
                {
                    continue;
                }

                if (!Arrays.contains(serverSupportedGroups, group))
                {
                    continue;
                }

                if (!crypto.hasNamedGroup(group))
                {
                    continue;
                }

                if ((NamedGroup.refersToASpecificCurve(group) && !crypto.hasECDHAgreement()) ||
                    (NamedGroup.refersToASpecificFiniteField(group) && !crypto.hasDHAgreement())) 
                {
                    continue;
                }

                return group;
            }
        }
        return -1;
    }

    static byte[] readEncryptedPMS(TlsContext context, InputStream input) throws IOException
    {
        if (isSSL(context))
        {
            return SSL3Utils.readEncryptedPMS(input);
        }

        return readOpaque16(input);
    }

    static void writeEncryptedPMS(TlsContext context, byte[] encryptedPMS, OutputStream output) throws IOException
    {
        if (isSSL(context))
        {
            SSL3Utils.writeEncryptedPMS(encryptedPMS, output);
        }
        else
        {
            writeOpaque16(encryptedPMS, output);
        }
    }

    static byte[] getSessionID(TlsSession tlsSession)
    {
        if (null != tlsSession)
        {
            byte[] sessionID = tlsSession.getSessionID();
            if (null != sessionID
                && sessionID.length > 0
                && sessionID.length <= 32)
            {
                return sessionID;
            }
        }
        return EMPTY_BYTES;
    }

    static void adjustTranscriptForRetry(TlsHandshakeHash handshakeHash)
        throws IOException
    {
        byte[] clientHelloHash = getCurrentPRFHash(handshakeHash);
        handshakeHash.reset();

        int length = clientHelloHash.length;
        checkUint8(length);

        byte[] synthetic = new byte[4 + length];
        writeUint8(HandshakeType.message_hash, synthetic, 0);
        writeUint24(length, synthetic, 1);
        System.arraycopy(clientHelloHash, 0, synthetic, 4, length);

        handshakeHash.update(synthetic, 0, synthetic.length);
    }

    static TlsCredentials establishClientCredentials(TlsAuthentication clientAuthentication,
        CertificateRequest certificateRequest) throws IOException
    {
        return validateCredentials(clientAuthentication.getClientCredentials(certificateRequest));
    }

    static TlsCredentialedSigner establish13ClientCredentials(TlsAuthentication clientAuthentication,
        CertificateRequest certificateRequest) throws IOException
    {
        return validate13Credentials(clientAuthentication.getClientCredentials(certificateRequest));
    }

    static void establishClientSigAlgs(SecurityParameters securityParameters, Hashtable clientExtensions)
        throws IOException
    {
        securityParameters.clientSigAlgs = TlsExtensionsUtils.getSignatureAlgorithmsExtension(clientExtensions);
        securityParameters.clientSigAlgsCert = TlsExtensionsUtils.getSignatureAlgorithmsCertExtension(clientExtensions);
    }

    static TlsCredentials establishServerCredentials(TlsServer server) throws IOException
    {
        return validateCredentials(server.getCredentials());
    }

    static TlsCredentialedSigner establish13ServerCredentials(TlsServer server) throws IOException
    {
        return validate13Credentials(server.getCredentials());
    }

    static void establishServerSigAlgs(SecurityParameters securityParameters, CertificateRequest certificateRequest)
        throws IOException
    {
        securityParameters.clientCertTypes = certificateRequest.getCertificateTypes();
        securityParameters.serverSigAlgs = certificateRequest.getSupportedSignatureAlgorithms();
        securityParameters.serverSigAlgsCert = certificateRequest.getSupportedSignatureAlgorithmsCert();

        if (null == securityParameters.getServerSigAlgsCert())
        {
            securityParameters.serverSigAlgsCert = securityParameters.getServerSigAlgs();
        }
    }

    static TlsCredentials validateCredentials(TlsCredentials credentials) throws IOException
    {
        if (null != credentials)
        {
            int count = 0;
            count += (credentials instanceof TlsCredentialedAgreement) ? 1 : 0;
            count += (credentials instanceof TlsCredentialedDecryptor) ? 1 : 0;
            count += (credentials instanceof TlsCredentialedSigner) ? 1 : 0;
            if (count != 1)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }
        return credentials;
    }

    static TlsCredentialedSigner validate13Credentials(TlsCredentials credentials) throws IOException
    {
        if (null == credentials)
        {
            return null;
        }
        if (!(credentials instanceof TlsCredentialedSigner))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        return (TlsCredentialedSigner)credentials;
    }

    static void negotiatedCipherSuite(SecurityParameters securityParameters, int cipherSuite) throws IOException
    {
        securityParameters.cipherSuite = cipherSuite;
        securityParameters.keyExchangeAlgorithm = getKeyExchangeAlgorithm(cipherSuite);

        int prfAlgorithm = getPRFAlgorithm(securityParameters, cipherSuite);
        securityParameters.prfAlgorithm = prfAlgorithm;

        switch (prfAlgorithm)
        {
        case PRFAlgorithm.ssl_prf_legacy:
        case PRFAlgorithm.tls_prf_legacy:
        {
            securityParameters.prfHashAlgorithm = -1;
            securityParameters.prfHashLength = -1;
            break;
        }
        default:
        {
            short prfHashAlgorithm = getHashAlgorithmForPRFAlgorithm(prfAlgorithm);

            securityParameters.prfHashAlgorithm = prfHashAlgorithm;
            securityParameters.prfHashLength = HashAlgorithm.getOutputSize(prfHashAlgorithm);
            break;
        }
        }

        /*
         * TODO[tls13] We're slowly moving towards negotiating cipherSuite THEN version. We could
         * move this to "after parameter negotiation" i.e. after ServerHello/EncryptedExtensions.
         */
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        if (isTLSv13(negotiatedVersion))
        {
            securityParameters.verifyDataLength = securityParameters.getPRFHashLength();
        }
        else
        {
            securityParameters.verifyDataLength = negotiatedVersion.isSSL() ? 36 : 12;
        }
    }

    static void negotiatedVersion(SecurityParameters securityParameters) throws IOException
    {
        if (!isSignatureAlgorithmsExtensionAllowed(securityParameters.getNegotiatedVersion()))
        {
            securityParameters.clientSigAlgs = null;
            securityParameters.clientSigAlgsCert = null;
            return;
        }

        if (null == securityParameters.getClientSigAlgs())
        {
            securityParameters.clientSigAlgs = getLegacySupportedSignatureAlgorithms();
        }

        if (null == securityParameters.getClientSigAlgsCert())
        {
            securityParameters.clientSigAlgsCert = securityParameters.getClientSigAlgs();
        }
    }

    static void negotiatedVersionDTLSClient(TlsClientContext clientContext, TlsClient client) throws IOException
    {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();

        if (!ProtocolVersion.isSupportedDTLSVersionClient(negotiatedVersion))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        negotiatedVersion(securityParameters);

        client.notifyServerVersion(negotiatedVersion);
    }

    static void negotiatedVersionDTLSServer(TlsServerContext serverContext) throws IOException
    {
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();

        if (!ProtocolVersion.isSupportedDTLSVersionServer(negotiatedVersion))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        negotiatedVersion(securityParameters);
    }

    static void negotiatedVersionTLSClient(TlsClientContext clientContext, TlsClient client) throws IOException
    {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();

        if (!ProtocolVersion.isSupportedTLSVersionClient(negotiatedVersion))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        negotiatedVersion(securityParameters);

        client.notifyServerVersion(negotiatedVersion);
    }

    static void negotiatedVersionTLSServer(TlsServerContext serverContext) throws IOException
    {
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();

        if (!ProtocolVersion.isSupportedTLSVersionServer(negotiatedVersion))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        negotiatedVersion(securityParameters);
    }

    static TlsSecret deriveSecret(SecurityParameters securityParameters, TlsSecret secret, String label,
        byte[] transcriptHash) throws IOException
    {
        return TlsCryptoUtils.hkdfExpandLabel(secret, securityParameters.getPRFHashAlgorithm(), label, transcriptHash,
            securityParameters.getPRFHashLength());
    }

    static TlsSecret getSessionMasterSecret(TlsCrypto crypto, TlsSecret masterSecret)
    {
        if (null != masterSecret)
        {
            synchronized (masterSecret)
            {
                if (masterSecret.isAlive())
                {
                    return crypto.adoptSecret(masterSecret);
                }
            }
        }

        return null;
    }

    static boolean isPermittedExtensionType13(int handshakeType, int extensionType)
    {
        switch (extensionType)
        {
        case ExtensionType.server_name:
        case ExtensionType.max_fragment_length:
        case ExtensionType.supported_groups:
        case ExtensionType.use_srtp:
        case ExtensionType.heartbeat:
        case ExtensionType.application_layer_protocol_negotiation:
        case ExtensionType.client_certificate_type:
        case ExtensionType.server_certificate_type:
        {
            switch (handshakeType)
            {
            case HandshakeType.client_hello:
            case HandshakeType.encrypted_extensions:
                return true;
            default:
                return false;
            }
        }
        case ExtensionType.status_request:
        case ExtensionType.signed_certificate_timestamp:
        {
            switch (handshakeType)
            {
            case HandshakeType.client_hello:
            case HandshakeType.certificate_request:
            case HandshakeType.certificate:
                return true;
            default:
                return false;
            }
        }
        case ExtensionType.signature_algorithms:
        case ExtensionType.certificate_authorities:
        case ExtensionType.signature_algorithms_cert:
        {
            switch (handshakeType)
            {
            case HandshakeType.client_hello:
            case HandshakeType.certificate_request:
                return true;
            default:
                return false;
            }
        }
        case ExtensionType.padding:
        case ExtensionType.psk_key_exchange_modes:
        case ExtensionType.post_handshake_auth:
        {
            switch (handshakeType)
            {
            case HandshakeType.client_hello:
                return true;
            default:
                return false;
            }
        }
        case ExtensionType.key_share:
        case ExtensionType.supported_versions:
        {
            switch (handshakeType)
            {
            case HandshakeType.client_hello:
            case HandshakeType.server_hello:
            case HandshakeType.hello_retry_request:
                return true;
            default:
                return false;
            }
        }
        case ExtensionType.pre_shared_key:
        {
            switch (handshakeType)
            {
            case HandshakeType.client_hello:
            case HandshakeType.server_hello:
                return true;
            default:
                return false;
            }
        }
        case ExtensionType.early_data:
        {
            switch (handshakeType)
            {
            case HandshakeType.client_hello:
            case HandshakeType.encrypted_extensions:
            case HandshakeType.new_session_ticket:
                return true;
            default:
                return false;
            }
        }
        case ExtensionType.cookie:
        {
            switch (handshakeType)
            {
            case HandshakeType.client_hello:
            case HandshakeType.hello_retry_request:
                return true;
            default:
                return false;
            }
        }
        case ExtensionType.oid_filters:
        {
            switch (handshakeType)
            {
            case HandshakeType.certificate_request:
                return true;
            default:
                return false;
            }
        }
        default:
        {
            return !ExtensionType.isRecognized(extensionType);
        }
        }
    }

    static void checkExtensionData13(Hashtable extensions, int handshakeType, short alertDescription) throws IOException
    {
        Enumeration e = extensions.keys();
        while (e.hasMoreElements())
        {
            Integer extensionType = (Integer)e.nextElement();
            if (null == extensionType || !isPermittedExtensionType13(handshakeType, extensionType.intValue()))
            {
                throw new TlsFatalAlert(alertDescription, "Invalid extension: " + ExtensionType.getText(extensionType.intValue()));
            }
        }
    }
}
