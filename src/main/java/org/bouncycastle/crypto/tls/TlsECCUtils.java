package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.util.Integers;

public class TlsECCUtils {

    private static final String[] curveNames = new String[] { "sect163k1", "sect163r1",
        "sect163r2", "sect193r1", "sect193r2", "sect233k1", "sect233r1", "sect239k1", "sect283k1",
        "sect283r1", "sect409k1", "sect409r1", "sect571k1", "sect571r1", "secp160k1", "secp160r1",
        "secp160r2", "secp192k1", "secp192r1", "secp224k1", "secp224r1", "secp256k1", "secp256r1",
        "secp384r1", "secp521r1", };

    public static boolean containsECCCipherSuites(int[] cipherSuites) {
        for (int i = 0; i < cipherSuites.length; ++i) {
            if (isECCCipherSuite(cipherSuites[i])) {
                return true;
            }
        }
        return false;
    }

    public static void addSupportedEllipticCurvesExtension(Hashtable extensions, int[] namedCurves)
        throws IOException {

        extensions.put(Integers.valueOf(ExtensionType.elliptic_curves),
            TlsECCUtils.createSupportedEllipticCurvesExtension(namedCurves));
    }

    public static void addSupportedPointFormatsExtension(Hashtable extensions,
        short[] ecPointFormats) throws IOException {

        extensions.put(Integers.valueOf(ExtensionType.ec_point_formats),
            TlsECCUtils.createSupportedPointFormatsExtension(ecPointFormats));
    }

    public static byte[] createSupportedEllipticCurvesExtension(int[] namedCurves)
        throws IOException {

        if (namedCurves == null || namedCurves.length < 1) {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsUtils.writeUint16(2 * namedCurves.length, buf);
        TlsUtils.writeUint16Array(namedCurves, buf);
        return buf.toByteArray();
    }

    public static byte[] createSupportedPointFormatsExtension(short[] ecPointFormats)
        throws IOException {

        if (ecPointFormats == null) {
            ecPointFormats = new short[] { ECPointFormat.uncompressed };
        } else if (!TlsProtocol.arrayContains(ecPointFormats, ECPointFormat.uncompressed)) {
            /*
             * RFC 4492 5.1. If the Supported Point Formats Extension is indeed sent, it MUST
             * contain the value 0 (uncompressed) as one of the items in the list of point formats.
             */

            // NOTE: We add it at the end (lowest preference)
            short[] tmp = new short[ecPointFormats.length + 1];
            System.arraycopy(ecPointFormats, 0, tmp, 0, ecPointFormats.length);
            tmp[ecPointFormats.length] = ECPointFormat.uncompressed;

            ecPointFormats = tmp;
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsUtils.writeUint8((short) ecPointFormats.length, buf);
        TlsUtils.writeUint8Array(ecPointFormats, buf);
        return buf.toByteArray();
    }

    public static String getNameOfNamedCurve(int namedCurve) {
        int index = namedCurve - 1;
        if (index < 0 || index >= curveNames.length) {
            return null;
        }

        return curveNames[index];
    }

    public static ECDomainParameters getParametersForNamedCurve(int namedCurve) {
        String curveName = getNameOfNamedCurve(namedCurve);
        if (curveName == null) {
            return null;
        }

        // Lazily created the first time a particular curve is accessed
        X9ECParameters ecP = SECNamedCurves.getByName(curveName);

        if (ecP == null) {
            return null;
        }

        // It's a bit inefficient to do this conversion every time
        return new ECDomainParameters(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(),
            ecP.getSeed());
    }

    public static boolean isECCCipherSuite(int cipherSuite) {
        switch (cipherSuite) {
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
            return true;
        default:
            return false;
        }

    }
}
