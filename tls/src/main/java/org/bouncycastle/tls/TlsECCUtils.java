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
    public static final Integer EXT_ec_point_formats = Integers.valueOf(ExtensionType.ec_point_formats);

    public static void addSupportedPointFormatsExtension(Hashtable extensions, short[] ecPointFormats)
        throws IOException
    {
        extensions.put(EXT_ec_point_formats, createSupportedPointFormatsExtension(ecPointFormats));
    }

    public static short[] getSupportedPointFormatsExtension(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_ec_point_formats);
        return extensionData == null ? null : readSupportedPointFormatsExtension(extensionData);
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
        /*
         * NOTE: This mechanism was added to support a minimum bit-size requirement mooted in
         * draft-ietf-tls-ecdhe-psk-aead-00. This requirement was removed in later drafts, so this
         * mechanism is currently somewhat trivial.
         */
        return isECCipherSuite(cipherSuite) ? 1 : 0;
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

    public static short getCompressionFormat(int namedGroup) throws IOException
    {
        if (NamedGroup.isPrimeCurve(namedGroup))
        {
            return ECPointFormat.ansiX962_compressed_prime;
        }
        if (NamedGroup.isChar2Curve(namedGroup))
        {
            return ECPointFormat.ansiX962_compressed_char2;
        }
        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
    }

    public static boolean isCompressionPreferred(short[] peerECPointFormats, int namedGroup) throws IOException
    {
        return isCompressionPreferred(peerECPointFormats, getCompressionFormat(namedGroup));
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

    public static void checkPointEncoding(short[] localECPointFormats, int namedGroup, byte[] encoding) throws IOException
    {
        if (encoding == null || encoding.length < 1)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        short actualFormat = getActualFormat(namedGroup, encoding);
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

    public static short getActualFormat(int namedGroup, byte[] encoding) throws IOException
    {
        switch (encoding[0])
        {
        case 0x02: // compressed
        case 0x03: // compressed
        {
            return getCompressionFormat(namedGroup);
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

        int namedGroup = TlsUtils.readUint16(input);
        if (!NamedGroup.refersToASpecificCurve(namedGroup))
        {
            /*
             * RFC 4492 5.4. All those values of NamedCurve are allowed that refer to a
             * specific curve. Values of NamedCurve that indicate support for a class of
             * explicitly defined curves are not allowed here [...].
             */
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        boolean compressed = isCompressionPreferred(peerECPointFormats, namedGroup);

        TlsECConfig result = new TlsECConfig();
        result.setNamedGroup(namedGroup);
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
        writeNamedECParameters(ecConfig.getNamedGroup(), output);
    }

    public static void writeNamedECParameters(int namedGroup, OutputStream output) throws IOException
    {
        if (!NamedGroup.refersToASpecificCurve(namedGroup))
        {
            /*
             * RFC 4492 5.4. All those values of NamedCurve are allowed that refer to a specific
             * curve. Values of NamedCurve that indicate support for a class of explicitly defined
             * curves are not allowed here [...].
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        TlsUtils.writeUint8(ECCurveType.named_curve, output);
        TlsUtils.checkUint16(namedGroup);
        TlsUtils.writeUint16(namedGroup, output);
    }
}
