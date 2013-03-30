package org.bouncycastle.crypto.tls;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

/**
 * Some helper functions for MicroTLS.
 */
public class TlsUtils
{
    protected static void writeUint8(short i, OutputStream os) throws IOException
    {
        os.write(i);
    }

    protected static void writeUint8(short i, byte[] buf, int offset)
    {
        buf[offset] = (byte)i;
    }

    protected static void writeUint16(int i, OutputStream os) throws IOException
    {
        os.write(i >> 8);
        os.write(i);
    }

    protected static void writeUint16(int i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 8);
        buf[offset + 1] = (byte)i;
    }

    protected static void writeUint24(int i, OutputStream os) throws IOException
    {
        os.write(i >> 16);
        os.write(i >> 8);
        os.write(i);
    }

    protected static void writeUint24(int i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 16);
        buf[offset + 1] = (byte)(i >> 8);
        buf[offset + 2] = (byte)(i);
    }

    protected static void writeUint32(long i, OutputStream os) throws IOException
    {
        os.write((int)(i >> 24));
        os.write((int)(i >> 16));
        os.write((int)(i >> 8));
        os.write((int)(i));
    }

    protected static void writeUint32(long i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 24);
        buf[offset + 1] = (byte)(i >> 16);
        buf[offset + 2] = (byte)(i >> 8);
        buf[offset + 3] = (byte)(i);
    }

    protected static void writeUint48(long i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 40);
        buf[offset + 1] = (byte)(i >> 32);
        buf[offset + 2] = (byte)(i >> 24);
        buf[offset + 3] = (byte)(i >> 16);
        buf[offset + 4] = (byte)(i >> 8);
        buf[offset + 5] = (byte)(i);
    }

    protected static void writeUint64(long i, OutputStream os) throws IOException
    {
        os.write((int)(i >> 56));
        os.write((int)(i >> 48));
        os.write((int)(i >> 40));
        os.write((int)(i >> 32));
        os.write((int)(i >> 24));
        os.write((int)(i >> 16));
        os.write((int)(i >> 8));
        os.write((int)(i));
    }

    protected static void writeUint64(long i, byte[] buf, int offset)
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

    protected static void writeOpaque8(byte[] buf, OutputStream os) throws IOException
    {
        writeUint8((short)buf.length, os);
        os.write(buf);
    }

    protected static void writeOpaque16(byte[] buf, OutputStream os) throws IOException
    {
        writeUint16(buf.length, os);
        os.write(buf);
    }

    protected static void writeOpaque24(byte[] buf, OutputStream os) throws IOException
    {
        writeUint24(buf.length, os);
        os.write(buf);
    }

    protected static void writeUint8Array(short[] uints, OutputStream os) throws IOException
    {
        for (int i = 0; i < uints.length; ++i)
        {
            writeUint8(uints[i], os);
        }
    }

    protected static void writeUint16Array(int[] uints, OutputStream os) throws IOException
    {
        for (int i = 0; i < uints.length; ++i)
        {
            writeUint16(uints[i], os);
        }
    }

    protected static short readUint8(InputStream is) throws IOException
    {
        int i = is.read();
        if (i < 0)
        {
            throw new EOFException();
        }
        return (short)i;
    }

    protected static short readUint8(byte[] buf, int offset)
    {
        return (short)buf[offset];
    }

    protected static int readUint16(InputStream is) throws IOException
    {
        int i1 = is.read();
        int i2 = is.read();
        if (i2 < 0)
        {
            throw new EOFException();
        }
        return i1 << 8 | i2;
    }

    protected static int readUint16(byte[] buf, int offset)
    {
        int n = (buf[offset] & 0xff) << 8;
        n |= (buf[++offset] & 0xff);
        return n;
    }

    protected static int readUint24(InputStream is) throws IOException
    {
        int i1 = is.read();
        int i2 = is.read();
        int i3 = is.read();
        if (i3 < 0)
        {
            throw new EOFException();
        }
        return (i1 << 16) | (i2 << 8) | i3;
    }

    protected static int readUint24(byte[] buf, int offset)
    {
        int n = (buf[offset] & 0xff) << 16;
        n |= (buf[++offset] & 0xff) << 8;
        n |= (buf[++offset] & 0xff);
        return n;
    }

    protected static long readUint32(InputStream is) throws IOException
    {
        int i1 = is.read();
        int i2 = is.read();
        int i3 = is.read();
        int i4 = is.read();
        if (i4 < 0)
        {
            throw new EOFException();
        }
        return (((long)i1) << 24) | (((long)i2) << 16) | (((long)i3) << 8) | ((long)i4);
    }

    protected static long readUint48(InputStream is) throws IOException
    {
        int i1 = is.read();
        int i2 = is.read();
        int i3 = is.read();
        int i4 = is.read();
        int i5 = is.read();
        int i6 = is.read();
        if (i6 < 0)
        {
            throw new EOFException();
        }
        return (((long)i1) << 40) | (((long)i2) << 32) | (((long)i3) << 24) | (((long)i4) << 16) | (((long)i5) << 8)  | ((long)i6);
    }

    protected static long readUint48(byte[] buf, int offset)
    {
        int hi = readUint24(buf, offset);
        int lo = readUint24(buf, offset + 3);
        return ((long)(hi & 0xffffffffL) << 24) | (long)(lo & 0xffffffffL);
    }

    protected static void readFully(byte[] buf, InputStream is) throws IOException
    {
        if (Streams.readFully(is, buf) != buf.length)
        {
            throw new EOFException();
        }
    }

    protected static byte[] readOpaque8(InputStream is) throws IOException
    {
        short length = readUint8(is);
        byte[] value = new byte[length];
        readFully(value, is);
        return value;
    }

    protected static byte[] readOpaque16(InputStream is) throws IOException
    {
        int length = readUint16(is);
        byte[] value = new byte[length];
        readFully(value, is);
        return value;
    }

    protected static byte[] readOpaque24(InputStream is) throws IOException
    {
        int length = readUint24(is);
        byte[] value = new byte[length];
        readFully(value, is);
        return value;
    }

    protected static short[] readUint8Array(int count, InputStream is) throws IOException
    {
        short[] uints = new short[count];
        for (int i = 0; i < count; ++i)
        {
            uints[i] = readUint8(is);
        }
        return uints;
    }

    protected static int[] readUint16Array(int count, InputStream is) throws IOException
    {
        int[] uints = new int[count];
        for (int i = 0; i < count; ++i)
        {
            uints[i] = readUint16(is);
        }
        return uints;
    }

    protected static ProtocolVersion readVersion(byte[] buf, int offset) throws IOException
    {
        return ProtocolVersion.get(buf[offset] & 0xFF, buf[offset + 1] & 0xFF);
    }

    protected static ProtocolVersion readVersion(InputStream is) throws IOException
    {
        int i1 = is.read();
        int i2 = is.read();
        if (i2 < 0)
        {
            throw new EOFException();
        }
        return ProtocolVersion.get(i1, i2);
    }

    protected static int readVersionRaw(InputStream is) throws IOException
    {
        int i1 = is.read();
        int i2 = is.read();
        if (i2 < 0)
        {
            throw new EOFException();
        }
        return (i1 << 8) | i2;
    }

    protected static void writeGMTUnixTime(byte[] buf, int offset)
    {
        int t = (int)(System.currentTimeMillis() / 1000L);
        buf[offset] = (byte)(t >> 24);
        buf[offset + 1] = (byte)(t >> 16);
        buf[offset + 2] = (byte)(t >> 8);
        buf[offset + 3] = (byte)t;
    }

    protected static void writeVersion(ProtocolVersion version, OutputStream os) throws IOException
    {
        os.write(version.getMajorVersion());
        os.write(version.getMinorVersion());
    }

    protected static void writeVersion(ProtocolVersion version, byte[] buf, int offset) throws IOException
    {
        buf[offset] = (byte)version.getMajorVersion();
        buf[offset + 1] = (byte)version.getMinorVersion();
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

    static byte[] PRF(TlsContext context, byte[] secret, String asciiLabel, byte[] seed, int size)
    {
        // TODO The PRFAlgorithm of the session should be available from the SecurityParameters

        return PRF_1_2(context, PRFAlgorithm.tls_prf_legacy, secret, asciiLabel, seed, size);
    }

    static byte[] PRF_1_2(TlsContext context, int prfAlgorithm, byte[] secret, String asciiLabel,
        byte[] seed, int size)
    {
        ProtocolVersion version = context.getServerVersion();

        if (version.isSSL()) {
            throw new IllegalStateException("No PRF available for SSLv3 session");
        }

        byte[] label = Strings.toByteArray(asciiLabel);
        byte[] labelSeed = concat(label, seed);

        // TODO The PRFAlgorithm of the session should be available from the SecurityParameters

        if (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
        {
            if (!ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(version)
                && !ProtocolVersion.DTLSv12.isEqualOrEarlierVersionOf(version))
            {
                return PRF_legacy(secret, label, labelSeed, size);
            }

            prfAlgorithm = PRFAlgorithm.tls_prf_sha256;
        }

        Digest prfDigest = getPRFDigest(prfAlgorithm);
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

    static void validateKeyUsage(org.bouncycastle.asn1.x509.Certificate c, int keyUsageBits) throws IOException
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

    static byte[] calculateKeyBlock(TlsContext context, int prfAlgorithm, int size)
    {
        SecurityParameters securityParameters = context.getSecurityParameters();
        byte[] master_secret = securityParameters.getMasterSecret();
        byte[] seed = concat(securityParameters.getServerRandom(),
            securityParameters.getClientRandom());

        if (prfAlgorithm == PRFAlgorithm.tls_prf_legacy && context.getServerVersion().isSSL())
        {
            return calculateKeyBlock_SSL(master_secret, seed, size);
        }

        return PRF_1_2(context, prfAlgorithm, master_secret, ExporterLabel.key_expansion, seed,
            size);
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

        byte[] master_secret = context.getSecurityParameters().getMasterSecret();

        return PRF(context, master_secret, asciiLabel, handshakeHash, 12);
    }

    static final Digest getPRFDigest(int prfAlgorithm)
    {
        switch (prfAlgorithm)
        {
        case PRFAlgorithm.tls_prf_legacy:
            throw new IllegalArgumentException("legacy PRF not a valid algorithm");
        case PRFAlgorithm.tls_prf_sha256:
            return new SHA256Digest();
        case PRFAlgorithm.tls_prf_sha384:
            return new SHA384Digest();
        default:
            throw new IllegalArgumentException("unknown PRF algorithm");
        }
    }

    static final byte[] SSL_CLIENT = { 0x43, 0x4C, 0x4E, 0x54 };
    static final byte[] SSL_SERVER = { 0x53, 0x52, 0x56, 0x52 };

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
}
