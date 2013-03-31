package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Vector;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

public abstract class DTLSProtocol {

    protected static final Integer EXT_RenegotiationInfo = Integers
        .valueOf(ExtensionType.renegotiation_info);

    protected final SecureRandom secureRandom;

    protected DTLSProtocol(SecureRandom secureRandom) {

        if (secureRandom == null)
            throw new IllegalArgumentException("'secureRandom' cannot be null");

        this.secureRandom = secureRandom;
    }

    protected void processFinished(byte[] body, byte[] verify_data) throws IOException {

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        byte[] serverVerifyData = TlsUtils.readFully(12, buf);

        TlsProtocol.assertEmpty(buf);

        if (!Arrays.constantTimeAreEqual(verify_data, serverVerifyData)) {
            // TODO Alert
            // this.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
        }
    }

    protected static byte[] generateCertificate(Certificate certificate) throws IOException {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificate.encode(buf);
        return buf.toByteArray();
    }

    protected static byte[] generateSupplementalData(Vector supplementalData) throws IOException {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsProtocol.writeSupplementalData(buf, supplementalData);
        return buf.toByteArray();
    }

    protected static void validateSelectedCipherSuite(int selectedCipherSuite,
        short alertDescription) throws IOException {

        switch (selectedCipherSuite) {
        case CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5:
        case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
        case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5:
        case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
        case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA:
            // TODO Alert
            throw new IllegalStateException(
                "Server selected an RC4 cipher suite: RC4 MUST NOT be used with DTLS");
        }
    }
}
