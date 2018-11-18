package org.bouncycastle.tls;

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

            // NOTE: We add it at the start (highest preference)
            ecPointFormats = Arrays.prepend(ecPointFormats, ECPointFormat.uncompressed);
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

    public static int getMinimumCurveBits(int cipherSuite)
    {
        /*
         * NOTE: This mechanism was added to support a minimum bit-size requirement mooted in early
         * drafts of RFC 8442. This requirement was removed in later drafts, so this mechanism is
         * currently somewhat trivial.
         */
        return isECCCipherSuite(cipherSuite) ? 1 : 0;
    }

    public static boolean isECCCipherSuite(int cipherSuite)
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

    public static void checkPointEncoding(int namedGroup, byte[] encoding) throws IOException
    {
        if (encoding == null || encoding.length < 1)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        switch (namedGroup)
        {
        case NamedGroup.x25519:
        case NamedGroup.x448:
            return;
        }

        switch (encoding[0])
        {
        case 0x04: // uncompressed
            return;

        case 0x00: // infinity
        case 0x02: // compressed
        case 0x03: // compressed
        case 0x06: // hybrid
        case 0x07: // hybrid
        default:
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
    }

    public static TlsECConfig readECConfig(InputStream input)
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

        TlsECConfig result = new TlsECConfig();
        result.setNamedGroup(namedGroup);
        return result;
    }

    public static TlsECConfig receiveECConfig(TlsECConfigVerifier ecConfigVerifier, InputStream input)
        throws IOException
    {
        TlsECConfig ecConfig = readECConfig(input);
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
