package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.io.Streams;

/**
 * Some helper functions for the TLS API.
 */
public class TlsUtils
{
    // Map OID strings to HashAlgorithm values
    private static final Hashtable sigHashAlgs = createSigHashAlgs();

    private static void addSigHashAlg(Hashtable h, ASN1ObjectIdentifier oid, short hashAlg)
    {
        h.put(oid.getId(), hashAlg);
    }

    private static Hashtable createSigHashAlgs()
    {
        Hashtable h = new Hashtable();

        addSigHashAlg(h, NISTObjectIdentifiers.dsa_with_sha224, HashAlgorithm.sha224);
        addSigHashAlg(h, NISTObjectIdentifiers.dsa_with_sha256, HashAlgorithm.sha256);
        addSigHashAlg(h, NISTObjectIdentifiers.dsa_with_sha384, HashAlgorithm.sha384);
        addSigHashAlg(h, NISTObjectIdentifiers.dsa_with_sha512, HashAlgorithm.sha512);

        addSigHashAlg(h, OIWObjectIdentifiers.dsaWithSHA1, HashAlgorithm.sha1);
        addSigHashAlg(h, OIWObjectIdentifiers.md5WithRSA, HashAlgorithm.md5);
        addSigHashAlg(h, OIWObjectIdentifiers.sha1WithRSA, HashAlgorithm.sha1);

        addSigHashAlg(h, PKCSObjectIdentifiers.md5WithRSAEncryption, HashAlgorithm.md5);
        addSigHashAlg(h, PKCSObjectIdentifiers.sha1WithRSAEncryption, HashAlgorithm.sha1);
        addSigHashAlg(h, PKCSObjectIdentifiers.sha224WithRSAEncryption, HashAlgorithm.sha224);
        addSigHashAlg(h, PKCSObjectIdentifiers.sha256WithRSAEncryption, HashAlgorithm.sha256);
        addSigHashAlg(h, PKCSObjectIdentifiers.sha384WithRSAEncryption, HashAlgorithm.sha384);
        addSigHashAlg(h, PKCSObjectIdentifiers.sha512WithRSAEncryption, HashAlgorithm.sha512);

        addSigHashAlg(h, X9ObjectIdentifiers.ecdsa_with_SHA1, HashAlgorithm.sha1);
        addSigHashAlg(h, X9ObjectIdentifiers.ecdsa_with_SHA224, HashAlgorithm.sha224);
        addSigHashAlg(h, X9ObjectIdentifiers.ecdsa_with_SHA256, HashAlgorithm.sha256);
        addSigHashAlg(h, X9ObjectIdentifiers.ecdsa_with_SHA384, HashAlgorithm.sha384);
        addSigHashAlg(h, X9ObjectIdentifiers.ecdsa_with_SHA512, HashAlgorithm.sha512);
        addSigHashAlg(h, X9ObjectIdentifiers.id_dsa_with_sha1, HashAlgorithm.sha1);

        addSigHashAlg(h, EACObjectIdentifiers.id_TA_ECDSA_SHA_1, HashAlgorithm.sha1);
        addSigHashAlg(h, EACObjectIdentifiers.id_TA_ECDSA_SHA_224, HashAlgorithm.sha224);
        addSigHashAlg(h, EACObjectIdentifiers.id_TA_ECDSA_SHA_256, HashAlgorithm.sha256);
        addSigHashAlg(h, EACObjectIdentifiers.id_TA_ECDSA_SHA_384, HashAlgorithm.sha384);
        addSigHashAlg(h, EACObjectIdentifiers.id_TA_ECDSA_SHA_512, HashAlgorithm.sha512);
        addSigHashAlg(h, EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_1, HashAlgorithm.sha1);
        addSigHashAlg(h, EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_256, HashAlgorithm.sha256);
        addSigHashAlg(h, EACObjectIdentifiers.id_TA_RSA_PSS_SHA_1, HashAlgorithm.sha1);
        addSigHashAlg(h, EACObjectIdentifiers.id_TA_RSA_PSS_SHA_256, HashAlgorithm.sha256);

        addSigHashAlg(h, BSIObjectIdentifiers.ecdsa_plain_SHA1, HashAlgorithm.sha1);
        addSigHashAlg(h, BSIObjectIdentifiers.ecdsa_plain_SHA224, HashAlgorithm.sha224);
        addSigHashAlg(h, BSIObjectIdentifiers.ecdsa_plain_SHA256, HashAlgorithm.sha256);
        addSigHashAlg(h, BSIObjectIdentifiers.ecdsa_plain_SHA384, HashAlgorithm.sha384);
        addSigHashAlg(h, BSIObjectIdentifiers.ecdsa_plain_SHA512, HashAlgorithm.sha512);

        return h;
    }

    public static final byte[] EMPTY_BYTES = new byte[0];
    public static final short[] EMPTY_SHORTS = new short[0];
    public static final int[] EMPTY_INTS = new int[0];
    public static final long[] EMPTY_LONGS = new long[0];

    public static final Integer EXT_signature_algorithms = Integers.valueOf(ExtensionType.signature_algorithms);

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

    public static byte[] encodeOpaque8(byte[] buf)
        throws IOException
    {
        checkUint8(buf.length);
        return Arrays.prepend(buf, (byte)buf.length);
    }

    public static byte[] encodeUint8(short uint) throws IOException
    {
        checkUint8(uint);

        byte[] extensionData = new byte[1];
        writeUint8(uint, extensionData, 0);
        return extensionData;
    }

    public static byte[] encodeUint8ArrayWithUint8Length(short[] uints) throws IOException
    {
        byte[] result = new byte[1 + uints.length];
        writeUint8ArrayWithUint8Length(uints, result, 0);
        return result;
    }

    public static byte[] encodeUint16ArrayWithUint16Length(int[] uints) throws IOException
    {
        int length = 2 * uints.length;
        byte[] result = new byte[2 + length];
        writeUint16ArrayWithUint16Length(uints, result, 0);
        return result;
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

    public static byte[] readOpaque16(InputStream input)
        throws IOException
    {
        int length = readUint16(input);
        return readFully(length, input);
    }

    public static byte[] readOpaque24(InputStream input)
        throws IOException
    {
        int length = readUint24(input);
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
        throws IOException
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

    public static int readVersionRaw(byte[] buf, int offset)
        throws IOException
    {
        return (buf[offset] << 8) | buf[offset + 1];
    }

    public static int readVersionRaw(InputStream input)
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

    public static Vector getAllSignatureAlgorithms()
    {
        Vector v = new Vector(4);
        v.addElement(SignatureAlgorithm.anonymous);
        v.addElement(SignatureAlgorithm.rsa);
        v.addElement(SignatureAlgorithm.dsa);
        v.addElement(SignatureAlgorithm.ecdsa);
        return v;
    }

    public static Vector getDefaultDSSSignatureAlgorithms()
    {
        return vectorOfOne(new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.dsa));
    }

    public static Vector getDefaultECDSASignatureAlgorithms()
    {
        return vectorOfOne(new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.ecdsa));
    }

    public static Vector getDefaultRSASignatureAlgorithms()
    {
        return vectorOfOne(new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.rsa));
    }

    public static Vector getDefaultSignatureAlgorithms(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.dsa:
            return getDefaultDSSSignatureAlgorithms();
        case SignatureAlgorithm.ecdsa:
            return getDefaultECDSASignatureAlgorithms();
        case SignatureAlgorithm.rsa:
            return getDefaultRSASignatureAlgorithms();
        default:
            throw new IllegalArgumentException("unknown SignatureAlgorithm: " + SignatureAlgorithm.getText(signatureAlgorithm));
        }
    }

    public static Vector getDefaultSupportedSignatureAlgorithms(TlsContext context)
    {
        TlsCrypto crypto = context.getCrypto();

        short[] hashAlgorithms = new short[]{ HashAlgorithm.sha1, HashAlgorithm.sha224, HashAlgorithm.sha256,
            HashAlgorithm.sha384, HashAlgorithm.sha512 };
        short[] signatureAlgorithms = new short[]{ SignatureAlgorithm.rsa, SignatureAlgorithm.dsa,
            SignatureAlgorithm.ecdsa };

        Vector result = new Vector();
        for (int i = 0; i < signatureAlgorithms.length; ++i)
        {
            for (int j = 0; j < hashAlgorithms.length; ++j)
            {
                SignatureAndHashAlgorithm alg = new SignatureAndHashAlgorithm(hashAlgorithms[j], signatureAlgorithms[i]);
                if (crypto.hasSignatureAndHashAlgorithm(alg))
                {
                    result.addElement(alg);
                }
            }
        }
        return result;
    }

    public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(TlsContext context,
        TlsCredentialedSigner signerCredentials)
        throws IOException
    {
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
        if (isTLSv12(context))
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

    public static boolean isSignatureAlgorithmsExtensionAllowed(ProtocolVersion clientVersion)
    {
        return ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(clientVersion.getEquivalentTLSVersion());
    }

    /**
     * Add a 'signature_algorithms' extension to existing extensions.
     *
     * @param extensions                   A {@link Hashtable} to add the extension to.
     * @param supportedSignatureAlgorithms {@link Vector} containing at least 1 {@link SignatureAndHashAlgorithm}.
     * @throws IOException
     */
    public static void addSignatureAlgorithmsExtension(Hashtable extensions, Vector supportedSignatureAlgorithms)
        throws IOException
    {
        extensions.put(EXT_signature_algorithms, createSignatureAlgorithmsExtension(supportedSignatureAlgorithms));
    }

    public static short getSignatureAlgorithm(int keyExchangeAlgorithm)
    {
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_DSS_EXPORT:
        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_DSS_EXPORT:
        case KeyExchangeAlgorithm.SRP_DSS:
            return SignatureAlgorithm.dsa;

        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
            return SignatureAlgorithm.ecdsa;

        case KeyExchangeAlgorithm.DH_RSA:
        case KeyExchangeAlgorithm.DH_RSA_EXPORT:
        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.DHE_RSA_EXPORT:
        case KeyExchangeAlgorithm.ECDH_RSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        case KeyExchangeAlgorithm.SRP_RSA:
            return SignatureAlgorithm.rsa;

        default:
            return -1;
        }
    }

    public static short getSignatureAlgorithmClient(short clientCertificateType)
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

    /**
     * Get a 'signature_algorithms' extension from extensions.
     *
     * @param extensions A {@link Hashtable} to get the extension from, if it is present.
     * @return A {@link Vector} containing at least 1 {@link SignatureAndHashAlgorithm}, or null.
     * @throws IOException
     */
    public static Vector getSignatureAlgorithmsExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = getExtensionData(extensions, EXT_signature_algorithms);
        return extensionData == null ? null : readSignatureAlgorithmsExtension(extensionData);
    }

    /**
     * Create a 'signature_algorithms' extension value.
     *
     * @param supportedSignatureAlgorithms A {@link Vector} containing at least 1 {@link SignatureAndHashAlgorithm}.
     * @return A byte array suitable for use as an extension value.
     * @throws IOException
     */
    public static byte[] createSignatureAlgorithmsExtension(Vector supportedSignatureAlgorithms)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        // supported_signature_algorithms
        encodeSupportedSignatureAlgorithms(supportedSignatureAlgorithms, false, buf);

        return buf.toByteArray();
    }

    /**
     * Read 'signature_algorithms' extension data.
     *
     * @param extensionData The extension data.
     * @return A {@link Vector} containing at least 1 {@link SignatureAndHashAlgorithm}.
     * @throws IOException
     */
    public static Vector readSignatureAlgorithmsExtension(byte[] extensionData)
        throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        // supported_signature_algorithms
        Vector supported_signature_algorithms = parseSupportedSignatureAlgorithms(false, buf);

        TlsProtocol.assertEmpty(buf);

        return supported_signature_algorithms;
    }

    public static void encodeSupportedSignatureAlgorithms(Vector supportedSignatureAlgorithms, boolean allowAnonymous,
        OutputStream output) throws IOException
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
            if (!allowAnonymous && entry.getSignature() == SignatureAlgorithm.anonymous)
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

    public static Vector parseSupportedSignatureAlgorithms(boolean allowAnonymous, InputStream input)
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
            SignatureAndHashAlgorithm entry = SignatureAndHashAlgorithm.parse(input);
            if (!allowAnonymous && entry.getSignature() == SignatureAlgorithm.anonymous)
            {
                /*
                 * RFC 5246 7.4.1.4.1 The "anonymous" value is meaningless in this context but used
                 * in Section 7.4.3. It MUST NOT appear in this extension.
                 */
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
            supportedSignatureAlgorithms.addElement(entry);
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

        if (signatureAlgorithm.getSignature() != SignatureAlgorithm.anonymous)
        {
            for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
            {
                SignatureAndHashAlgorithm entry = (SignatureAndHashAlgorithm)supportedSignatureAlgorithms.elementAt(i);
                if (entry.getHash() == signatureAlgorithm.getHash() && entry.getSignature() == signatureAlgorithm.getSignature())
                {
                    return;
                }
            }
        }

        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
    }

    public static TlsSecret PRF(TlsContext context, TlsSecret secret, String asciiLabel, byte[] seed, int length)
    {
        int prfAlgorithm = context.getSecurityParameters().getPrfAlgorithm();

        return secret.deriveUsingPRF(prfAlgorithm, asciiLabel, seed, length);
    }

    static byte[] concat(byte[] a, byte[] b)
    {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    static byte[] calculateEndPointHash(TlsContext context, String sigAlgOID, byte[] enc)
    {
        return calculateEndPointHash(context, sigAlgOID, enc, 0, enc.length);
    }

    static byte[] calculateEndPointHash(TlsContext context, String sigAlgOID, byte[] enc, int encOff, int encLen)
    {
        if (sigAlgOID != null)
        {
            Short hashAlgObj = (Short)sigHashAlgs.get(sigAlgOID);
            if (hashAlgObj != null)
            {
                short hashAlg = hashAlgObj.shortValue();
                switch (hashAlg)
                {
                case HashAlgorithm.md5:
                case HashAlgorithm.sha1:
                    hashAlg = HashAlgorithm.sha256;
                    break;
                }

                TlsHash hash = context.getCrypto().createHash(hashAlg);
                if (hash != null)
                {                
                    hash.update(enc, encOff, encLen);
                    return hash.calculateHash();
                }
            }
        }
        return EMPTY_BYTES;
    }

    static TlsSecret calculateMasterSecret(TlsContext context, TlsSecret preMasterSecret)
    {
        String asciiLabel;
        byte[] seed;
        if (context.getSecurityParameters().isExtendedMasterSecret())
        {
            asciiLabel = ExporterLabel.extended_master_secret;
            seed = context.getSecurityParameters().getSessionHash();
        }
        else
        {
            asciiLabel = ExporterLabel.master_secret;
            seed = concat(context.getSecurityParameters().getClientRandom(), context.getSecurityParameters().getServerRandom());
        }

        return PRF(context, preMasterSecret, asciiLabel, seed, 48);
    }

    static byte[] calculateTLSVerifyData(TlsContext context, TlsHandshakeHash handshakeHash, boolean isServer)
    {
        String asciiLabel = isServer ? ExporterLabel.server_finished : ExporterLabel.client_finished;
        byte[] prfHash = getCurrentPRFHash(handshakeHash);

        return calculateTLSVerifyData(context, asciiLabel, prfHash);
    }

    static byte[] calculateTLSVerifyData(TlsContext context, String asciiLabel, byte[] prfHash)
    {
        SecurityParameters securityParameters = context.getSecurityParameters();
        TlsSecret master_secret = securityParameters.getMasterSecret();
        int verify_data_length = securityParameters.getVerifyDataLength();

        return PRF(context, master_secret, asciiLabel, prfHash, verify_data_length).extract();
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
        case PRFAlgorithm.tls_prf_legacy:
            throw new IllegalArgumentException("legacy PRF not a valid algorithm");
        case PRFAlgorithm.tls_prf_sha256:
            return HashAlgorithm.sha256;
        case PRFAlgorithm.tls_prf_sha384:
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
            throw new IllegalArgumentException("unknown HashAlgorithm: " + HashAlgorithm.getText(hashAlgorithm));
        }
    }

    static byte[] calculateSignatureHash(TlsContext context, SignatureAndHashAlgorithm algorithm, DigestInputBuffer buf)
    {
        TlsCrypto crypto = context.getCrypto();

        TlsHash h = algorithm == null
            ? new CombinedHash(crypto)
            : crypto.createHash(algorithm.getHash());

        SecurityParameters securityParameters = context.getSecurityParameters();
        h.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        h.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        buf.updateDigest(h);

        return h.calculateHash();
    }

    static void sendSignatureInput(TlsContext context, DigestInputBuffer buf, OutputStream output)
        throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParameters();
        // NOTE: The implicit copy here is intended (and important)
        output.write(Arrays.concatenate(securityParameters.clientRandom, securityParameters.serverRandom));
        buf.copyTo(output);
        output.close();
    }

    static DigitallySigned generateCertificateVerify(TlsContext context, TlsCredentialedSigner credentialedSigner,
        TlsStreamSigner streamSigner, TlsHandshakeHash handshakeHash) throws IOException
    {
        /*
         * RFC 5246 4.7. digitally-signed element needs SignatureAndHashAlgorithm from TLS 1.2
         */
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = getSignatureAndHashAlgorithm(
            context, credentialedSigner);

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
                hash = context.getSecurityParameters().getSessionHash();
            }
            else
            {
                hash = handshakeHash.getFinalHash(signatureAndHashAlgorithm.getHash());
            }

            signature = credentialedSigner.generateRawSignature(hash);
        }

        return new DigitallySigned(signatureAndHashAlgorithm, signature);
    }

    static void verifyCertificateVerify(TlsContext context, CertificateRequest certificateRequest, Certificate certificate,
        DigitallySigned certificateVerify, TlsHandshakeHash handshakeHash) throws IOException
    {
        short certificateType = certificate.getCertificateAt(0).getClientCertificateType();

        // Verify the CertificateVerify message contains a correct signature.
        boolean verified;
        try
        {
            TlsVerifier verifier = certificate.getCertificateAt(0)
                .createVerifier(getSignatureAlgorithmClient(certificateType));
            TlsStreamVerifier streamVerifier = verifier.getStreamVerifier(certificateVerify);

            if (streamVerifier != null)
            {
                handshakeHash.copyBufferTo(streamVerifier.getOutputStream());
                verified = streamVerifier.isVerified();
            }
            else
            {
                SignatureAndHashAlgorithm signatureAlgorithm = certificateVerify.getAlgorithm();
    
                byte[] hash;
                if (isTLSv12(context))
                {
                    verifySupportedSignatureAlgorithm(certificateRequest.getSupportedSignatureAlgorithms(), signatureAlgorithm);
                    hash = handshakeHash.getFinalHash(signatureAlgorithm.getHash());
                }
                else
                {
                    hash = context.getSecurityParameters().getSessionHash();
                }

                verified = verifier.verifyRawSignature(certificateVerify, hash);
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

    static DigitallySigned generateServerKeyExchangeSignature(TlsContext context, TlsCredentialedSigner credentials,
        DigestInputBuffer buf) throws IOException
    {
        /*
         * RFC 5246 4.7. digitally-signed element needs SignatureAndHashAlgorithm from TLS 1.2
         */
        SignatureAndHashAlgorithm algorithm = getSignatureAndHashAlgorithm(context, credentials);
        TlsStreamSigner streamSigner = credentials.getStreamSigner();

        byte[] signature;
        if (streamSigner != null)
        {
            sendSignatureInput(context, buf, streamSigner.getOutputStream());
            signature = streamSigner.getSignature();
        }
        else
        {
            byte[] hash = calculateSignatureHash(context, algorithm, buf);
            signature = credentials.generateRawSignature(hash);
        }

        return new DigitallySigned(algorithm, signature);
    }

    static void verifyServerKeyExchangeSignature(TlsContext context, TlsVerifier verifier, DigestInputBuffer buf,
        DigitallySigned signedParams) throws IOException
    {
        TlsStreamVerifier streamVerifier = verifier.getStreamVerifier(signedParams);

        boolean verified;
        if (streamVerifier != null)
        {
            sendSignatureInput(context, buf, streamVerifier.getOutputStream());
            verified = streamVerifier.isVerified();
        }
        else
        {
            byte[] hash = calculateSignatureHash(context, signedParams.getAlgorithm(), buf);
            verified = verifier.verifyRawSignature(signedParams, hash);
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

                // TODO Support values in the "Reserved for Private Use" range
                if (!HashAlgorithm.isPrivate(hashAlgorithm))
                {
                    handshakeHash.trackHashAlgorithm(hashAlgorithm);
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

    static final byte[] SSL_CLIENT = {0x43, 0x4C, 0x4E, 0x54};
    static final byte[] SSL_SERVER = {0x53, 0x52, 0x56, 0x52};

    private static Vector vectorOfOne(Object obj)
    {
        Vector v = new Vector(1);
        v.addElement(obj);
        return v;
    }

    public static int getCipherType(int cipherSuite)
    {
        switch (getEncryptionAlgorithm(cipherSuite))
        {
        case EncryptionAlgorithm.AES_128_CCM:
        case EncryptionAlgorithm.AES_128_CCM_8:
        case EncryptionAlgorithm.AES_128_GCM:
        case EncryptionAlgorithm.AES_128_OCB_TAGLEN96:
        case EncryptionAlgorithm.AES_256_CCM:
        case EncryptionAlgorithm.AES_256_CCM_8:
        case EncryptionAlgorithm.AES_256_GCM:
        case EncryptionAlgorithm.ARIA_128_GCM:
        case EncryptionAlgorithm.ARIA_256_GCM:
        case EncryptionAlgorithm.AES_256_OCB_TAGLEN96:
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

        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
            return EncryptionAlgorithm.AES_128_CCM;

        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
            return EncryptionAlgorithm.AES_128_CCM_8;

        case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
            return EncryptionAlgorithm.AES_128_GCM;

        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_128_OCB:
        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_128_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_128_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_128_OCB:
        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_128_OCB:
            return EncryptionAlgorithm.AES_128_OCB_TAGLEN96;

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

        case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
            return EncryptionAlgorithm.AES_256_GCM;

        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_256_OCB:
        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_256_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_256_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_256_OCB:
        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_256_OCB:
            return EncryptionAlgorithm.AES_256_OCB_TAGLEN96;

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

        case CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
            return EncryptionAlgorithm.CHACHA20_POLY1305;

        case CipherSuite.TLS_RSA_WITH_NULL_MD5:
            return EncryptionAlgorithm.NULL;

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

        case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
        case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
            return EncryptionAlgorithm.RC4_128;

        case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
        case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
            return EncryptionAlgorithm.RC4_128;

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
        case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
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
        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_128_OCB:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_256_OCB:
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
        case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
            return KeyExchangeAlgorithm.DHE_PSK;

        case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_128_OCB:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_256_OCB:
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
        case CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA:
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
        case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
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
        case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
            return KeyExchangeAlgorithm.ECDH_RSA;

        case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_128_OCB:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_256_OCB:
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
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
            return KeyExchangeAlgorithm.ECDHE_ECDSA;

        case CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_OCB:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_OCB:
        case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA:
            return KeyExchangeAlgorithm.ECDHE_PSK;

        case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_128_OCB:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_256_OCB:
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
        case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
            return KeyExchangeAlgorithm.ECDHE_RSA;

        case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_128_OCB:
        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_256_OCB:
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
        case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
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
        case CipherSuite.TLS_RSA_WITH_NULL_MD5:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
        case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
        case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
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
        case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
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

    public static int getMACAlgorithm(int cipherSuite)
    {
        switch (cipherSuite)
        {
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
        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_128_OCB:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_256_OCB:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_128_OCB:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_256_OCB:
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
        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_128_OCB:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_256_OCB:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_OCB:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_128_OCB:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_256_OCB:
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
        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_128_OCB:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_256_OCB:
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

        case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
        case CipherSuite.TLS_RSA_WITH_NULL_MD5:
        case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
            return MACAlgorithm.hmac_md5;

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
        case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
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
        case CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
        case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
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
        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_128_OCB:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_256_OCB:
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
        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_128_OCB:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_256_OCB:
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
        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_128_OCB:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_256_OCB:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_OCB:
        case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_128_OCB:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_256_OCB:
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
        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_128_OCB:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_256_OCB:
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

    public static boolean isValidCipherSuiteForSignatureAlgorithms(int cipherSuite, Vector sigAlgs)
    {
        int keyExchangeAlgorithm = getKeyExchangeAlgorithm(cipherSuite);

        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_anon:
        case KeyExchangeAlgorithm.DH_anon_EXPORT:
        case KeyExchangeAlgorithm.ECDH_anon:
            return sigAlgs.contains(SignatureAlgorithm.anonymous);

        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.DHE_RSA_EXPORT:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        case KeyExchangeAlgorithm.SRP_RSA:
            return sigAlgs.contains(SignatureAlgorithm.rsa);

        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_DSS_EXPORT:
        case KeyExchangeAlgorithm.SRP_DSS:
            return sigAlgs.contains(SignatureAlgorithm.dsa);

        case KeyExchangeAlgorithm.ECDHE_ECDSA:
            return sigAlgs.contains(SignatureAlgorithm.ecdsa);

        default:
            return true;
        }
    }

    public static boolean isValidCipherSuiteForVersion(int cipherSuite, ProtocolVersion serverVersion)
    {
        return getMinimumVersion(cipherSuite).isEqualOrEarlierVersionOf(serverVersion.getEquivalentTLSVersion());
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
            return getAllSignatureAlgorithms();
        }

        Vector v = new Vector(4);
        v.addElement(SignatureAlgorithm.anonymous);
        for (int i = 0; i < sigHashAlgs.size(); ++i)
        {
            SignatureAndHashAlgorithm sigHashAlg = (SignatureAndHashAlgorithm)sigHashAlgs.elementAt(i);
            if (sigHashAlg.getHash() >= MINIMUM_HASH_STRICT)
            {
                short sigAlg = sigHashAlg.getSignature();
                if (!v.contains(sigAlg))
                {
                    v.addElement(sigAlg);
                }
            }
        }
        return v;
    }

    public static int[] getSupportedCipherSuites(TlsCrypto crypto, int[] baseCipherSuiteList)
    {
        List<Integer> supported = new ArrayList<Integer>();

        for (int i = 0; i != baseCipherSuiteList.length; i++)
        {
            if (isSupportedCipherSuite(crypto, baseCipherSuiteList[i]))
            {
                supported.add(baseCipherSuiteList[i]);
            }
        }

        int[] rv = new int[supported.size()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = supported.get(i);
        }

        return rv;
    }

    public static boolean isSupportedCipherSuite(TlsCrypto crypto, int cipherSuite)
    {
        return isSupportedKeyExchange(crypto, getKeyExchangeAlgorithm(cipherSuite))
            && crypto.hasEncryptionAlgorithm(getEncryptionAlgorithm(cipherSuite))
            && crypto.hasMacAlgorithm(getMACAlgorithm(cipherSuite));
    }

    public static boolean isStaticKeyAgreement(int keyExchangeAlgorithm)
    {
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_DSS_EXPORT:
        case KeyExchangeAlgorithm.DH_RSA:
        case KeyExchangeAlgorithm.DH_RSA_EXPORT:
        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
            return true;

        default:
            return false;
        }
    }

    public static boolean isSupportedKeyExchange(TlsCrypto crypto, int keyExchangeAlgorithm)
    {
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_anon:
        case KeyExchangeAlgorithm.DH_anon_EXPORT:
        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_DSS_EXPORT:
        case KeyExchangeAlgorithm.DH_RSA:
        case KeyExchangeAlgorithm.DH_RSA_EXPORT:
        case KeyExchangeAlgorithm.DHE_PSK:
            return crypto.hasDHAgreement();

        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_DSS_EXPORT:
            return crypto.hasDHAgreement()
                && crypto.hasSignatureAlgorithm(SignatureAlgorithm.dsa);

        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.DHE_RSA_EXPORT:
            return crypto.hasDHAgreement()
                && crypto.hasSignatureAlgorithm(SignatureAlgorithm.rsa);

        case KeyExchangeAlgorithm.ECDH_anon:
        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
        case KeyExchangeAlgorithm.ECDHE_PSK:
            return crypto.hasECDHAgreement();

        case KeyExchangeAlgorithm.ECDHE_ECDSA:
            return crypto.hasECDHAgreement()
                && crypto.hasSignatureAlgorithm(SignatureAlgorithm.ecdsa);

        case KeyExchangeAlgorithm.ECDHE_RSA:
            return crypto.hasECDHAgreement()
                && crypto.hasSignatureAlgorithm(SignatureAlgorithm.rsa);

        case KeyExchangeAlgorithm.NULL:
        case KeyExchangeAlgorithm.PSK:
            return true;

        case KeyExchangeAlgorithm.RSA:
        case KeyExchangeAlgorithm.RSA_EXPORT:
        case KeyExchangeAlgorithm.RSA_PSK:
            return crypto.hasRSAEncryption();

        case KeyExchangeAlgorithm.SRP:
            return crypto.hasSRPAuthentication();

        case KeyExchangeAlgorithm.SRP_DSS:
            return crypto.hasSRPAuthentication()
                && crypto.hasSignatureAlgorithm(SignatureAlgorithm.dsa);

        case KeyExchangeAlgorithm.SRP_RSA:
            return crypto.hasSRPAuthentication()
                && crypto.hasSignatureAlgorithm(SignatureAlgorithm.rsa);

        default:
            return false;
        }
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

    static void processServerCertificate(Certificate serverCertificate, CertificateStatus serverCertificateStatus, TlsKeyExchange keyExchange,
        TlsAuthentication clientAuthentication, Hashtable clientExtensions, Hashtable serverExtensions) throws IOException
    {
        checkTlsFeatures(serverCertificate, clientExtensions, serverExtensions);
        keyExchange.processServerCertificate(serverCertificate);
        clientAuthentication.notifyServerCertificate(new TlsServerCertificateImpl(serverCertificate, serverCertificateStatus));
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

        return new CertificateRequest(retained, certificateRequest.getSupportedSignatureAlgorithms(),
            certificateRequest.getCertificateAuthorities());
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
}
