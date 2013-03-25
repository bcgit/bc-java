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

    protected static final byte[] EMPTY_BYTES = new byte[0];

    protected final SecureRandom secureRandom;

    protected DTLSProtocol(SecureRandom secureRandom) {

        if (secureRandom == null)
            throw new IllegalArgumentException("'secureRandom' cannot be null");

        this.secureRandom = secureRandom;
    }

    protected void processFinished(byte[] body, byte[] verify_data) throws IOException {

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        byte[] serverVerifyData = new byte[12];
        TlsUtils.readFully(serverVerifyData, buf);

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
}
