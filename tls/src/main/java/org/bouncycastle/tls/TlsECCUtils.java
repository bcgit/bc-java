package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Hashtable;

import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

public class TlsECCUtils
{
    public static final Integer EXT_elliptic_curves = Integers.valueOf(ExtensionType.elliptic_curves);
    public static final Integer EXT_ec_point_formats = Integers.valueOf(ExtensionType.ec_point_formats);

    public static void addSupportedEllipticCurvesExtension(Hashtable extensions, int[] namedCurves) throws IOException
    {
        extensions.put(EXT_elliptic_curves, createSupportedEllipticCurvesExtension(namedCurves));
    }

    public static void addSupportedPointFormatsExtension(Hashtable extensions, short[] ecPointFormats)
        throws IOException
    {
        extensions.put(EXT_ec_point_formats, createSupportedPointFormatsExtension(ecPointFormats));
    }

    public static int[] getSupportedEllipticCurvesExtension(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_elliptic_curves);
        return extensionData == null ? null : readSupportedEllipticCurvesExtension(extensionData);
    }

    public static short[] getSupportedPointFormatsExtension(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_ec_point_formats);
        return extensionData == null ? null : readSupportedPointFormatsExtension(extensionData);
    }

    public static byte[] createSupportedEllipticCurvesExtension(int[] namedCurves) throws IOException
    {
        if (namedCurves == null || namedCurves.length < 1)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return TlsUtils.encodeUint16ArrayWithUint16Length(namedCurves);
    }

    public static byte[] createSupportedPointFormatsExtension(short[] ecPointFormats) throws IOException
    {
        if (ecPointFormats == null || !Arrays.contains(ecPointFormats, ECPointFormat.uncompressed))
        {
            /*
             * RFC 4492 5.1. If the Supported Point Formats Extension is indeed sent, it MUST
             * contain the value 0 (uncompressed) as one of the items in the list of point formats.
             */

            // NOTE: We add it at the end (lowest preference)
            ecPointFormats = Arrays.append(ecPointFormats, ECPointFormat.uncompressed);
        }

        return TlsUtils.encodeUint8ArrayWithUint8Length(ecPointFormats);
    }

    public static int[] readSupportedEllipticCurvesExtension(byte[] extensionData) throws IOException
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

        int[] namedCurves = TlsUtils.readUint16Array(length / 2, buf);

        TlsProtocol.assertEmpty(buf);

        return namedCurves;
    }

    public static short[] readSupportedPointFormatsExtension(byte[] extensionData) throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        short length = TlsUtils.readUint8(buf);
        if (length < 1)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        short[] ecPointFormats = TlsUtils.readUint8Array(length, buf);

        TlsProtocol.assertEmpty(buf);

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

    public static boolean containsECCCipherSuites(int[] cipherSuites)
    {
        for (int i = 0; i < cipherSuites.length; ++i)
        {
            if (isECCCipherSuite(cipherSuites[i]))
            {
                return true;
            }
        }
        return false;
    }

    public static int getMinimumCurveBits(int cipherSuite)
    {
        switch (cipherSuite)
        {
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
            return 255;

        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_CCM_8_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_CCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
            return 384;

        default:
        {
            if (!isECCCipherSuite(cipherSuite))
            {
                return 0;
            }

            // TODO Is there a de facto rule to require a curve of similar size to the PRF hash?
            return 1;
        }
        }
    }

    public static boolean isECCCipherSuite(int cipherSuite)
    {
        switch (cipherSuite)
        {
        /*
         * RFC 4492
         */
        case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA:

        /*
         * RFC 5289
         */
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:

        /*
         * RFC 5489
         */
        case CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA:

        /*
         * RFC 6367
         */
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:

        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:

        case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:

        /*
         * RFC 7251
         */
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:

        /*
         * RFC 7905
         */
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:

        /*
         * draft-zauner-tls-aes-ocb-04
         */
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_128_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_256_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_128_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_256_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_OCB:

        /*
         * draft-ietf-tls-ecdhe-psk-aead-00
         */
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_CCM_8_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_CCM_SHA384:

            return true;

        default:
            return false;
        }
    }

    public static short getCompressionFormat(int namedCurve) throws IOException
    {
        if (NamedCurve.isPrime(namedCurve))
        {
            return ECPointFormat.ansiX962_compressed_prime;
        }
        if (NamedCurve.isChar2(namedCurve))
        {
            return ECPointFormat.ansiX962_compressed_char2;
        }
        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
    }

    public static boolean isCompressionPreferred(short[] peerECPointFormats, int namedCurve) throws IOException
    {
        return isCompressionPreferred(peerECPointFormats, getCompressionFormat(namedCurve));
    }

    public static boolean isCompressionPreferred(short[] peerECPointFormats, short compressionFormat)
    {
        if (peerECPointFormats == null || compressionFormat == ECPointFormat.uncompressed)
        {
            return false;
        }
        for (int i = 0; i < peerECPointFormats.length; ++i)
        {
            short ecPointFormat = peerECPointFormats[i];
            if (ecPointFormat == ECPointFormat.uncompressed)
            {
                return false;
            }
            if (ecPointFormat == compressionFormat)
            {
                return true;
            }
        }
        return false;
    }

    public static void checkPointEncoding(short[] localECPointFormats, int namedCurve, byte[] encoding) throws IOException
    {
        if (encoding == null || encoding.length < 1)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        short actualFormat = getActualFormat(namedCurve, encoding);
        checkActualFormat(localECPointFormats, actualFormat);
    }

    public static void checkActualFormat(short[] localECPointFormats, short actualFormat) throws IOException
    {
        if (actualFormat != ECPointFormat.uncompressed
            && (localECPointFormats == null || !Arrays.contains(localECPointFormats, actualFormat)))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
    }

    public static short getActualFormat(int namedCurve, byte[] encoding) throws IOException
    {
        switch (encoding[0])
        {
        case 0x02: // compressed
        case 0x03: // compressed
        {
            return getCompressionFormat(namedCurve);
        }
        case 0x04: // uncompressed
        {
            return ECPointFormat.uncompressed;
        }
        case 0x00: // infinity
        case 0x06: // hybrid
        case 0x07: // hybrid
        default:
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
    }

    public static TlsECConfig readECConfig(short[] peerECPointFormats, InputStream input)
        throws IOException
    {
        short curveType = TlsUtils.readUint8(input);
        if (curveType != ECCurveType.named_curve)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        int namedCurve = TlsUtils.readUint16(input);
        if (!NamedCurve.refersToASpecificNamedCurve(namedCurve))
        {
            /*
             * RFC 4492 5.4. All those values of NamedCurve are allowed that refer to a
             * specific curve. Values of NamedCurve that indicate support for a class of
             * explicitly defined curves are not allowed here [...].
             */
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        boolean compressed = isCompressionPreferred(peerECPointFormats, namedCurve);

        TlsECConfig result = new TlsECConfig();
        result.setNamedCurve(namedCurve);
        result.setPointCompression(compressed);
        return result;
    }

    public static TlsECConfig receiveECConfig(TlsECConfigVerifier ecConfigVerifier, short[] peerECPointFormats, InputStream input)
        throws IOException
    {
        TlsECConfig ecConfig = readECConfig(peerECPointFormats, input);
        if (!ecConfigVerifier.accept(ecConfig))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        return ecConfig;
    }

    public static void writeECConfig(TlsECConfig ecConfig, OutputStream output) throws IOException
    {
        writeNamedECParameters(ecConfig.getNamedCurve(), output);
    }

    public static void writeNamedECParameters(int namedCurve, OutputStream output) throws IOException
    {
        if (!NamedCurve.refersToASpecificNamedCurve(namedCurve))
        {
            /*
             * RFC 4492 5.4. All those values of NamedCurve are allowed that refer to a specific
             * curve. Values of NamedCurve that indicate support for a class of explicitly defined
             * curves are not allowed here [...].
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        TlsUtils.writeUint8(ECCurveType.named_curve, output);
        TlsUtils.checkUint16(namedCurve);
        TlsUtils.writeUint16(namedCurve, output);
    }
}
