package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.util.Arrays;

public abstract class DTLSProtocol
{
    protected DTLSProtocol()
    {
    }

    protected void processFinished(byte[] body, byte[] expected_verify_data)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        byte[] verify_data = TlsUtils.readFully(expected_verify_data.length, buf);

        TlsProtocol.assertEmpty(buf);

        if (!Arrays.constantTimeAreEqual(expected_verify_data, verify_data))
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
    }

    protected static void applyMaxFragmentLengthExtension(DTLSRecordLayer recordLayer, short maxFragmentLength)
        throws IOException
    {
        if (maxFragmentLength >= 0)
        {
            if (!MaxFragmentLength.isValid(maxFragmentLength))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error); 
            }

            int plainTextLimit = 1 << (8 + maxFragmentLength);
            recordLayer.setPlaintextLimit(plainTextLimit);
        }
    }

    protected static short evaluateMaxFragmentLengthExtension(boolean resumedSession, Hashtable clientExtensions,
        Hashtable serverExtensions, short alertDescription) throws IOException
    {
        short maxFragmentLength = TlsExtensionsUtils.getMaxFragmentLengthExtension(serverExtensions);
        if (maxFragmentLength >= 0)
        {
            if (!MaxFragmentLength.isValid(maxFragmentLength)
                || (!resumedSession && maxFragmentLength != TlsExtensionsUtils
                    .getMaxFragmentLengthExtension(clientExtensions)))
            {
                throw new TlsFatalAlert(alertDescription);
            }
        }
        return maxFragmentLength;
    }

    /** @deprecated */
    protected static byte[] generateCertificate(Certificate certificate)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificate.encode(buf);
        return buf.toByteArray();
    }

    protected static byte[] generateCertificate(TlsContext context, Certificate certificate, OutputStream endPointHash)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificate.encode(context, buf, endPointHash);
        return buf.toByteArray();
    }

    protected static byte[] generateSupplementalData(Vector supplementalData)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsProtocol.writeSupplementalData(buf, supplementalData);
        return buf.toByteArray();
    }

    protected byte[] createVerifyData(TlsContext context, DTLSReliableHandshake handshake, boolean isServer)
    {
        return TlsUtils.calculateTLSVerifyData(context, handshake.getHandshakeHash(), isServer);
    }

    protected static void validateSelectedCipherSuite(int selectedCipherSuite, short alertDescription)
        throws IOException
    {
        switch (TlsUtils.getEncryptionAlgorithm(selectedCipherSuite))
        {
        case EncryptionAlgorithm.RC4_40:
        case EncryptionAlgorithm.RC4_128:
        case -1:
            throw new TlsFatalAlert(alertDescription);
        }
    }
}
