package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

/**
 * Some helper functions for MicroTLS.
 */
public class TlsUtils
{
    public static byte[] EMPTY_BYTES = new byte[0];

    public static final Integer EXT_signature_algorithms = Integers.valueOf(ExtensionType.signature_algorithms);

    public static boolean isValidUint8(short i)
    {
        return (i & 0xFF) == i;
    }

    public static boolean isValidUint16(int i)
    {
        return (i & 0xFFFF) == i;
    }

    public static boolean isValidUint24(int i)
    {
        return (i & 0xFFFFFF) == i;
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

    public static void writeUint8(short i, OutputStream output)
        throws IOException
    {
        output.write(i);
    }

    public static void writeUint8(short i, byte[] buf, int offset)
    {
        buf[offset] = (byte)i;
    }

    public static void writeUint16(int i, OutputStream output)
        throws IOException
    {
        output.write(i >> 8);
        output.write(i);
    }

    public static void writeUint16(int i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 8);
        buf[offset + 1] = (byte)i;
    }

    public static void writeUint24(int i, OutputStream output)
        throws IOException
    {
        output.write(i >> 16);
        output.write(i >> 8);
        output.write(i);
    }

    public static void writeUint24(int i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 16);
        buf[offset + 1] = (byte)(i >> 8);
        buf[offset + 2] = (byte)(i);
    }

    public static void writeUint32(long i, OutputStream output)
        throws IOException
    {
        output.write((int)(i >> 24));
        output.write((int)(i >> 16));
        output.write((int)(i >> 8));
        output.write((int)(i));
    }

    public static void writeUint32(long i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 24);
        buf[offset + 1] = (byte)(i >> 16);
        buf[offset + 2] = (byte)(i >> 8);
        buf[offset + 3] = (byte)(i);
    }

    public static void writeUint48(long i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 40);
        buf[offset + 1] = (byte)(i >> 32);
        buf[offset + 2] = (byte)(i >> 24);
        buf[offset + 3] = (byte)(i >> 16);
        buf[offset + 4] = (byte)(i >> 8);
        buf[offset + 5] = (byte)(i);
    }

    public static void writeUint64(long i, OutputStream output)
        throws IOException
    {
        output.write((int)(i >> 56));
        output.write((int)(i >> 48));
        output.write((int)(i >> 40));
        output.write((int)(i >> 32));
        output.write((int)(i >> 24));
        output.write((int)(i >> 16));
        output.write((int)(i >> 8));
        output.write((int)(i));
    }

    public static void writeUint64(long i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 56);
        buf[offset + 1] = (byte)(i >> 48);
        buf[offset + 2] = (byte)(i >> 40);
        buf[offset + 3] = (byte)(i >> 32);
        buf[offset + 4] = (byte)(i >> 24);
        buf[offset + 5] = (byte)(i >> 16);
        buf[offset + 6] = (byte)(i >> 8);
        buf[offset + 7] = (byte)(i);
    }

    public static void writeOpaque8(byte[] buf, OutputStream output)
        throws IOException
    {
        writeUint8((short)buf.length, output);
        output.write(buf);
    }

    public static void writeOpaque16(byte[] buf, OutputStream output)
        throws IOException
    {
        writeUint16(buf.length, output);
        output.write(buf);
    }

    public static void writeOpaque24(byte[] buf, OutputStream output)
        throws IOException
    {
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

    public static void writeUint16Array(int[] uints, OutputStream output)
        throws IOException
    {
        for (int i = 0; i < uints.length; ++i)
        {
            writeUint16(uints[i], output);
        }
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
        return (short)buf[offset];
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
        return i1 << 8 | i2;
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
        return (((long)i1) << 24) | (((long)i2) << 16) | (((long)i3) << 8) | ((long)i4);
    }

    public static long readUint48(InputStream input)
        throws IOException
    {
        int i1 = input.read();
        int i2 = input.read();
        int i3 = input.read();
        int i4 = input.read();
        int i5 = input.read();
        int i6 = input.read();
        if (i6 < 0)
        {
            throw new EOFException();
        }
        return (((long)i1) << 40) | (((long)i2) << 32) | (((long)i3) << 24) | (((long)i4) << 16) | (((long)i5) << 8) | ((long)i6);
    }

    public static long readUint48(byte[] buf, int offset)
    {
        int hi = readUint24(buf, offset);
        int lo = readUint24(buf, offset + 3);
        return ((long)(hi & 0xffffffffL) << 24) | (long)(lo & 0xffffffffL);
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

    public static void writeGMTUnixTime(byte[] buf, int offset)
    {
        int t = (int)(System.currentTimeMillis() / 1000L);
        buf[offset] = (byte)(t >> 24);
        buf[offset + 1] = (byte)(t >> 16);
        buf[offset + 2] = (byte)(t >> 8);
        buf[offset + 3] = (byte)t;
    }

    public static void writeVersion(ProtocolVersion version, OutputStream output)
        throws IOException
    {
        output.write(version.getMajorVersion());
        output.write(version.getMinorVersion());
    }

    public static void writeVersion(ProtocolVersion version, byte[] buf, int offset)
        throws IOException
    {
        buf[offset] = (byte)version.getMajorVersion();
        buf[offset + 1] = (byte)version.getMinorVersion();
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

        if (extensions == null)
        {
            return null;
        }
        byte[] extensionValue = (byte[])extensions.get(EXT_signature_algorithms);
        if (extensionValue == null)
        {
            return null;
        }
        return readSignatureAlgorithmsExtension(extensionValue);
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

        if (supportedSignatureAlgorithms == null || supportedSignatureAlgorithms.size() < 1 || supportedSignatureAlgorithms.size() >= (1 << 15))
        {
            throw new IllegalArgumentException(
                "'supportedSignatureAlgorithms' must have length from 1 to (2^15 - 1)");
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        // supported_signature_algorithms
        TlsUtils.writeUint16(2 * supportedSignatureAlgorithms.size(), buf);
        for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
        {
            SignatureAndHashAlgorithm entry = (SignatureAndHashAlgorithm)supportedSignatureAlgorithms.elementAt(i);
            entry.encode(buf);
        }

        return buf.toByteArray();
    }

    /**
     * Read a 'signature_algorithms' extension value.
     *
     * @param extensionValue The extension value.
     * @return A {@link Vector} containing at least 1 {@link SignatureAndHashAlgorithm}.
     * @throws IOException
     */
    public static Vector readSignatureAlgorithmsExtension(byte[] extensionValue)
        throws IOException
    {

        if (extensionValue == null)
        {
            throw new IllegalArgumentException("'extensionValue' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionValue);

        // supported_signature_algorithms
        int length = TlsUtils.readUint16(buf);
        if (length < 2 || (length & 1) != 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        int count = length / 2;
        Vector result = new Vector(count);
        for (int i = 0; i < count; ++i)
        {
            SignatureAndHashAlgorithm entry = SignatureAndHashAlgorithm.parse(buf);
            result.addElement(entry);
        }

        TlsProtocol.assertEmpty(buf);

        return result;
    }

    public static byte[] PRF(TlsContext context, byte[] secret, String asciiLabel, byte[] seed, int size)
    {
        ProtocolVersion version = context.getServerVersion();

        if (version.isSSL())
        {
            throw new IllegalStateException("No PRF available for SSLv3 session");
        }

        byte[] label = Strings.toByteArray(asciiLabel);
        byte[] labelSeed = concat(label, seed);

        int prfAlgorithm = context.getSecurityParameters().getPrfAlgorithm();

        if (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
        {
            if (!ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion()))
            {
                return PRF_legacy(secret, label, labelSeed, size);
            }

            prfAlgorithm = PRFAlgorithm.tls_prf_sha256;
        }

        Digest prfDigest = createPRFHash(prfAlgorithm);
        byte[] buf = new byte[size];
        hmac_hash(prfDigest, secret, labelSeed, buf);
        return buf;
    }

    static byte[] PRF_legacy(byte[] secret, byte[] label, byte[] labelSeed, int size)
    {
        int s_half = (secret.length + 1) / 2;
        byte[] s1 = new byte[s_half];
        byte[] s2 = new byte[s_half];
        System.arraycopy(secret, 0, s1, 0, s_half);
        System.arraycopy(secret, secret.length - s_half, s2, 0, s_half);

        byte[] b1 = new byte[size];
        byte[] b2 = new byte[size];
        hmac_hash(new MD5Digest(), s1, labelSeed, b1);
        hmac_hash(new SHA1Digest(), s2, labelSeed, b2);
        for (int i = 0; i < size; i++)
        {
            b1[i] ^= b2[i];
        }
        return b1;
    }

    static byte[] concat(byte[] a, byte[] b)
    {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    static void hmac_hash(Digest digest, byte[] secret, byte[] seed, byte[] out)
    {
        HMac mac = new HMac(digest);
        KeyParameter param = new KeyParameter(secret);
        byte[] a = seed;
        int size = digest.getDigestSize();
        int iterations = (out.length + size - 1) / size;
        byte[] buf = new byte[mac.getMacSize()];
        byte[] buf2 = new byte[mac.getMacSize()];
        for (int i = 0; i < iterations; i++)
        {
            mac.init(param);
            mac.update(a, 0, a.length);
            mac.doFinal(buf, 0);
            a = buf;
            mac.init(param);
            mac.update(a, 0, a.length);
            mac.update(seed, 0, seed.length);
            mac.doFinal(buf2, 0);
            System.arraycopy(buf2, 0, out, (size * i), Math.min(size, out.length - (size * i)));
        }
    }

    static void validateKeyUsage(org.bouncycastle.asn1.x509.Certificate c, int keyUsageBits)
        throws IOException
    {
        Extensions exts = c.getTBSCertificate().getExtensions();
        if (exts != null)
        {
            KeyUsage ku = KeyUsage.fromExtensions(exts);
            if (ku != null)
            {
                int bits = ku.getBytes()[0] & 0xff;
                if ((bits & keyUsageBits) != keyUsageBits)
                {
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown);
                }
            }
        }
    }

    static byte[] calculateKeyBlock(TlsContext context, int size)
    {
        SecurityParameters securityParameters = context.getSecurityParameters();
        byte[] master_secret = securityParameters.getMasterSecret();
        byte[] seed = concat(securityParameters.getServerRandom(),
            securityParameters.getClientRandom());

        if (context.getServerVersion().isSSL())
        {
            return calculateKeyBlock_SSL(master_secret, seed, size);
        }

        return PRF(context, master_secret, ExporterLabel.key_expansion, seed, size);
    }

    static byte[] calculateKeyBlock_SSL(byte[] master_secret, byte[] random, int size)
    {
        Digest md5 = new MD5Digest();
        Digest sha1 = new SHA1Digest();
        int md5Size = md5.getDigestSize();
        byte[] shatmp = new byte[sha1.getDigestSize()];
        byte[] tmp = new byte[size + md5Size];

        int i = 0, pos = 0;
        while (pos < size)
        {
            byte[] ssl3Const = SSL3_CONST[i];

            sha1.update(ssl3Const, 0, ssl3Const.length);
            sha1.update(master_secret, 0, master_secret.length);
            sha1.update(random, 0, random.length);
            sha1.doFinal(shatmp, 0);

            md5.update(master_secret, 0, master_secret.length);
            md5.update(shatmp, 0, shatmp.length);
            md5.doFinal(tmp, pos);

            pos += md5Size;
            ++i;
        }

        byte rval[] = new byte[size];
        System.arraycopy(tmp, 0, rval, 0, size);
        return rval;
    }

    static byte[] calculateMasterSecret(TlsContext context, byte[] pre_master_secret)
    {
        SecurityParameters securityParameters = context.getSecurityParameters();
        byte[] seed = concat(securityParameters.getClientRandom(), securityParameters.getServerRandom());

        if (context.getServerVersion().isSSL())
        {
            return calculateMasterSecret_SSL(pre_master_secret, seed);
        }

        return PRF(context, pre_master_secret, ExporterLabel.master_secret, seed, 48);
    }

    static byte[] calculateMasterSecret_SSL(byte[] pre_master_secret, byte[] random)
    {
        Digest md5 = new MD5Digest();
        Digest sha1 = new SHA1Digest();
        int md5Size = md5.getDigestSize();
        byte[] shatmp = new byte[sha1.getDigestSize()];

        byte[] rval = new byte[md5Size * 3];
        int pos = 0;

        for (int i = 0; i < 3; ++i)
        {
            byte[] ssl3Const = SSL3_CONST[i];

            sha1.update(ssl3Const, 0, ssl3Const.length);
            sha1.update(pre_master_secret, 0, pre_master_secret.length);
            sha1.update(random, 0, random.length);
            sha1.doFinal(shatmp, 0);

            md5.update(pre_master_secret, 0, pre_master_secret.length);
            md5.update(shatmp, 0, shatmp.length);
            md5.doFinal(rval, pos);

            pos += md5Size;
        }

        return rval;
    }

    static byte[] calculateVerifyData(TlsContext context, String asciiLabel, byte[] handshakeHash)
    {
        if (context.getServerVersion().isSSL())
        {
            return handshakeHash;
        }

        SecurityParameters securityParameters = context.getSecurityParameters();
        byte[] master_secret = securityParameters.getMasterSecret();
        int verify_data_length = securityParameters.getVerifyDataLength();

        return PRF(context, master_secret, asciiLabel, handshakeHash, verify_data_length);
    }

    public static final Digest createHash(int hashAlgorithm)
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithm.md5:
            return new MD5Digest();
        case HashAlgorithm.sha1:
            return new SHA1Digest();
        case HashAlgorithm.sha224:
            return new SHA224Digest();
        case HashAlgorithm.sha256:
            return new SHA256Digest();
        case HashAlgorithm.sha384:
            return new SHA384Digest();
        case HashAlgorithm.sha512:
            return new SHA512Digest();
        default:
            throw new IllegalArgumentException("unknown HashAlgorithm");
        }
    }

    public static final Digest cloneHash(int hashAlgorithm, Digest hash)
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithm.md5:
            return new MD5Digest((MD5Digest)hash);
        case HashAlgorithm.sha1:
            return new SHA1Digest((SHA1Digest)hash);
        case HashAlgorithm.sha224:
            return new SHA224Digest((SHA224Digest)hash);
        case HashAlgorithm.sha256:
            return new SHA256Digest((SHA256Digest)hash);
        case HashAlgorithm.sha384:
            return new SHA384Digest((SHA384Digest)hash);
        case HashAlgorithm.sha512:
            return new SHA512Digest((SHA512Digest)hash);
        default:
            throw new IllegalArgumentException("unknown HashAlgorithm");
        }
    }

    public static final Digest createPRFHash(int prfAlgorithm)
    {
        switch (prfAlgorithm)
        {
        case PRFAlgorithm.tls_prf_legacy:
            return new CombinedHash();
        default:
            return createHash(getHashAlgorithmForPRFAlgorithm(prfAlgorithm));
        }
    }

    public static final Digest clonePRFHash(int prfAlgorithm, Digest hash)
    {
        switch (prfAlgorithm)
        {
        case PRFAlgorithm.tls_prf_legacy:
            return new CombinedHash((CombinedHash)hash);
        default:
            return cloneHash(getHashAlgorithmForPRFAlgorithm(prfAlgorithm), hash);
        }
    }

    public static final short getHashAlgorithmForPRFAlgorithm(int prfAlgorithm)
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
            throw new IllegalArgumentException("unknown PRFAlgorithm");
        }
    }

    public static ASN1ObjectIdentifier getOIDForHashAlgorithm(int hashAlgorithm)
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
            throw new IllegalArgumentException("unknown HashAlgorithm");
        }
    }

    static short getClientCertificateType(Certificate clientCertificate, Certificate serverCertificate)
        throws IOException
    {
        if (clientCertificate.isEmpty())
        {
            return -1;
        }

        org.bouncycastle.asn1.x509.Certificate x509Cert = clientCertificate.getCertificateAt(0);
        SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
        try
        {
            AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(keyInfo);
            if (publicKey.isPrivate())
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            /*
             * TODO RFC 5246 7.4.6. The certificates MUST be signed using an acceptable hash/
             * signature algorithm pair, as described in Section 7.4.4. Note that this relaxes the
             * constraints on certificate-signing algorithms found in prior versions of TLS.
             */

            /*
             * RFC 5246 7.4.6. Client Certificate
             */

            /*
             * RSA public key; the certificate MUST allow the key to be used for signing with the
             * signature scheme and hash algorithm that will be employed in the certificate verify
             * message.
             */
            if (publicKey instanceof RSAKeyParameters)
            {
                validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
                return ClientCertificateType.rsa_sign;
            }

            /*
             * DSA public key; the certificate MUST allow the key to be used for signing with the
             * hash algorithm that will be employed in the certificate verify message.
             */
            if (publicKey instanceof DSAPublicKeyParameters)
            {
                validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
                return ClientCertificateType.dss_sign;
            }

            /*
             * ECDSA-capable public key; the certificate MUST allow the key to be used for signing
             * with the hash algorithm that will be employed in the certificate verify message; the
             * public key MUST use a curve and point format supported by the server.
             */
            if (publicKey instanceof ECPublicKeyParameters)
            {
                validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
                // TODO Check the curve and point format
                return ClientCertificateType.ecdsa_sign;
            }

            // TODO Add support for ClientCertificateType.*_fixed_*

        }
        catch (Exception e)
        {
        }

        throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
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

    public static TlsSigner createTlsSigner(short clientCertificateType)
    {
        switch (clientCertificateType)
        {
        case ClientCertificateType.dss_sign:
            return new TlsDSSSigner();
        case ClientCertificateType.ecdsa_sign:
            return new TlsECDSASigner();
        case ClientCertificateType.rsa_sign:
            return new TlsRSASigner();
        default:
            throw new IllegalArgumentException("'clientCertificateType' is not a type with signing capability");
        }
    }

    static final byte[] SSL_CLIENT = {0x43, 0x4C, 0x4E, 0x54};
    static final byte[] SSL_SERVER = {0x53, 0x52, 0x56, 0x52};

    // SSL3 magic mix constants ("A", "BB", "CCC", ...)
    static final byte[][] SSL3_CONST = genConst();

    private static byte[][] genConst()
    {
        int n = 10;
        byte[][] arr = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            byte[] b = new byte[i + 1];
            Arrays.fill(b, (byte)('A' + i));
            arr[i] = b;
        }
        return arr;
    }

    private static Vector vectorOfOne(Object obj)
    {
        Vector v = new Vector(1);
        v.addElement(obj);
        return v;
    }
}
