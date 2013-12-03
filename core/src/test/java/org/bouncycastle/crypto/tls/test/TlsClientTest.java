package org.bouncycastle.crypto.tls.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.MaxFragmentLength;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClient;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsExtensionsUtils;
import org.bouncycastle.crypto.tls.TlsSession;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * A simple test designed to conduct a TLS handshake with an external TLS server.
 * <p/>
 * Please refer to GnuTLSSetup.txt or OpenSSLSetup.txt, and x509-*.pem files in this package for
 * help configuring an external TLS server.
 */
public class TlsClientTest
{
    private static final SecureRandom secureRandom = new SecureRandom();

    public static void main(String[] args)
        throws Exception
    {
        InetAddress address = InetAddress.getLocalHost();
        int port = 5556;

        long time1 = System.currentTimeMillis();

        MyTlsClient client = new MyTlsClient(null);
        TlsClientProtocol protocol = openTlsConnection(address, port, client);
        protocol.close();

        long time2 = System.currentTimeMillis();
        System.out.println("Elapsed 1: " + (time2 - time1) + "ms");

        client = new MyTlsClient(client.getSessionToResume());
        protocol = openTlsConnection(address, port, client);

        long time3 = System.currentTimeMillis();
        System.out.println("Elapsed 2: " + (time3 - time2) + "ms");

        OutputStream output = protocol.getOutputStream();
        output.write("GET / HTTP/1.1\r\n\r\n".getBytes("UTF-8"));
        output.flush();

        InputStream input = protocol.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(input));

        String line;
        while ((line = reader.readLine()) != null)
        {
            System.out.println(">>> " + line);
        }

        protocol.close();
    }

    static TlsClientProtocol openTlsConnection(InetAddress address, int port, TlsClient client) throws IOException
    {
        Socket s = new Socket(address, port);
        TlsClientProtocol protocol = new TlsClientProtocol(s.getInputStream(), s.getOutputStream(), secureRandom);
        protocol.connect(client);
        return protocol;
    }

    static class MyTlsClient
        extends DefaultTlsClient
    {
        TlsSession session;

        MyTlsClient(TlsSession session)
        {
            this.session = session;
        }

        public TlsSession getSessionToResume()
        {
            return this.session;
        }

        public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Exception cause)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS client raised alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
                + ")");
            if (message != null)
            {
                out.println(message);
            }
            if (cause != null)
            {
                cause.printStackTrace(out);
            }
        }

        public void notifyAlertReceived(short alertLevel, short alertDescription)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS client received alert (AlertLevel." + alertLevel + ", AlertDescription."
                + alertDescription + ")");
        }

        public Hashtable getClientExtensions() throws IOException
        {
            Hashtable clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(super.getClientExtensions());
            TlsExtensionsUtils.addMaxFragmentLengthExtension(clientExtensions, MaxFragmentLength.pow2_9);
            TlsExtensionsUtils.addTruncatedHMacExtension(clientExtensions);
            // For testing draft-gutmann-tls-encrypt-then-mac
//            clientExtensions.put(Integers.valueOf(0x42), TlsExtensionsUtils.createEmptyExtensionData());
            return clientExtensions;
        }

        public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
        {
            super.notifyServerVersion(serverVersion);

            System.out.println("Negotiated " + serverVersion);
        }

        public TlsAuthentication getAuthentication()
            throws IOException
        {
            return new TlsAuthentication()
            {
                public void notifyServerCertificate(org.bouncycastle.crypto.tls.Certificate serverCertificate)
                    throws IOException
                {
                    Certificate[] chain = serverCertificate.getCertificateList();
                    System.out.println("Received server certificate chain of length " + chain.length);
                    for (int i = 0; i != chain.length; i++)
                    {
                        Certificate entry = chain[i];
                        // TODO Create fingerprint based on certificate signature algorithm digest
                        System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                            + entry.getSubject() + ")");
                    }
                }

                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
                    throws IOException
                {
                    short[] certificateTypes = certificateRequest.getCertificateTypes();
                    if (certificateTypes == null || !Arrays.contains(certificateTypes, ClientCertificateType.rsa_sign))
                    {
                        return null;
                    }

                    SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
                    Vector sigAlgs = certificateRequest.getSupportedSignatureAlgorithms();
                    if (sigAlgs != null)
                    {
                        for (int i = 0; i < sigAlgs.size(); ++i)
                        {
                            SignatureAndHashAlgorithm sigAlg = (SignatureAndHashAlgorithm)
                                sigAlgs.elementAt(i);
                            if (sigAlg.getSignature() == SignatureAlgorithm.rsa)
                            {
                                signatureAndHashAlgorithm = sigAlg;
                                break;
                            }
                        }

                        if (signatureAndHashAlgorithm == null)
                        {
                            return null;
                        }
                    }

                    // TODO Create a distinct client certificate for use here
                    return TlsTestUtils.loadSignerCredentials(context, new String[] { "x509-server.pem", "x509-ca.pem" },
                        "x509-server-key.pem", signatureAndHashAlgorithm);
                }
            };
        }

        public void notifyHandshakeComplete() throws IOException
        {
            super.notifyHandshakeComplete();

            TlsSession newSession = context.getResumableSession();
            if (newSession != null)
            {
                byte[] newSessionID = newSession.getSessionID();
                String hex = Hex.toHexString(newSessionID);

                if (this.session != null && Arrays.areEqual(this.session.getSessionID(), newSessionID))
                {
                    System.out.println("Resumed session: " + hex);
                }
                else
                {
                    System.out.println("Established session: " + hex);
                }

                this.session = newSession;
            }
        }
    }
}
