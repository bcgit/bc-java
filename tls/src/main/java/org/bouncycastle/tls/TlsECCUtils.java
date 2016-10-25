package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Set;

import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

public class TlsECCUtils
{
    public static final Integer EXT_elliptic_curves = Integers.valueOf(ExtensionType.supported_groups);
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

    public static int[] getSupportedEllipticCurvesExtension(Hashtable extensions, Set<Integer> acceptedCurves) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_elliptic_curves);
        return extensionData == null ? null : readSupportedEllipticCurvesExtension(extensionData, acceptedCurves);
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

    public static int[] readSupportedEllipticCurvesExtension(byte[] extensionData, Set<Integer> acceptedCurves) throws IOException
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

        //
        // check the proposed list is acceptable
        //
        int count = 0;
        for (int i = 0; i != namedCurves.length; i++)
        {
            if (acceptedCurves.contains(namedCurves[i]))
            {
                count++;
            }
        }

        if (count == 0)
        {
            return null;
        }

        // prune list if necessary
        if (count != namedCurves.length)
        {
            int ind = 0;
            int[] acceptedNamedCurves = new int[count];
            for (int i = 0; i != namedCurves.length; i++)
            {
                if (acceptedCurves.contains(namedCurves[i]))
                {
                    acceptedNamedCurves[ind++] = namedCurves[i];
                }
            }

            return acceptedNamedCurves;
        }

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

    public static boolean containsECCipherSuites(int[] cipherSuites)
    {
        for (int i = 0; i < cipherSuites.length; ++i)
        {
            if (isECCipherSuite(cipherSuites[i]))
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
            if (!isECCipherSuite(cipherSuite))
            {
                return 0;
            }

            // TODO Is there a de facto rule to require a curve of similar size to the PRF hash?
            return 1;
        }
        }
    }

    public static boolean isECCipherSuite(int cipherSuite)
    {
        switch (TlsUtils.getKeyExchangeAlgorithm(cipherSuite))
        {
        case KeyExchangeAlgorithm.ECDH_anon:
        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_PSK:
        case KeyExchangeAlgorithm.ECDHE_RSA:
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
