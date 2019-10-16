package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Hashtable;

import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.util.Arrays;

public class TlsECCUtils
{
    public static TlsECConfig createNamedECConfig(TlsContext context, int namedGroup)
        throws IOException
    {
        if (NamedGroup.getCurveBits(namedGroup) < 1)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return new TlsECConfig(namedGroup);
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

    public static TlsECConfig receiveECDHConfig(TlsContext context, InputStream input) throws IOException
    {
        short curveType = TlsUtils.readUint8(input);
        if (curveType != ECCurveType.named_curve)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        int namedGroup = TlsUtils.readUint16(input);
        if (NamedGroup.refersToAnECDHCurve(namedGroup))
        {
            int[] clientSupportedGroups = context.getSecurityParametersHandshake().getClientSupportedGroups();
            if (null == clientSupportedGroups || Arrays.contains(clientSupportedGroups, namedGroup))
            {
                return new TlsECConfig(namedGroup);
            }
        }

        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
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
