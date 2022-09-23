package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.tls.CertificateType;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.io.TeeOutputStream;

/**
 * A simple test designed to conduct a TLS handshake with an external TLS client.
 *
 * gnutls-cli --rawpkkeyfile ed25519.priv --rawpkfile ed25519.pub --priority NORMAL:+CTYPE-CLI-RAWPK:+CTYPE-SRV-RAWPK --insecure --debug 10 --port 5556 localhost
 */
public class TlsServerRawKeysTest
{
    public static void main(String[] args)
        throws Exception
    {
        InetAddress address = InetAddress.getLoopbackAddress();
        int port = 5556;
        ProtocolVersion[] tlsVersions = ProtocolVersion.TLSv13.downTo(ProtocolVersion.TLSv12);

        ServerSocket ss = new ServerSocket(port, 16, address);
        try
        {
            for (int i = 0; i != tlsVersions.length; i++)
            {
                ProtocolVersion tlsVersion = tlsVersions[i];
                Socket s = ss.accept();
                System.out.println("--------------------------------------------------------------------------------");
                System.out.println("Accepted " + s);
                ServerThread t = new ServerThread(s, tlsVersion);
                t.start();
            }
        }
        finally
        {
            ss.close();
        }
    }

    static class ServerThread
        extends Thread
    {
        private final Socket s;
        private final ProtocolVersion tlsVersion;

        ServerThread(Socket s, ProtocolVersion tlsVersion)
        {
            this.s = s;
            this.tlsVersion = tlsVersion;
        }

        public void run()
        {
            try
            {
                MockRawKeysTlsServer server = new MockRawKeysTlsServer(
                        CertificateType.RawPublicKey,
                        CertificateType.RawPublicKey,
                        new short[] {CertificateType.RawPublicKey},
                        new Ed25519PrivateKeyParameters(new SecureRandom()),
                        tlsVersion);
                TlsServerProtocol serverProtocol = new TlsServerProtocol(s.getInputStream(), s.getOutputStream());
                serverProtocol.accept(server);
                OutputStream log = new TeeOutputStream(serverProtocol.getOutputStream(), System.out);
                Streams.pipeAll(serverProtocol.getInputStream(), log);
                serverProtocol.close();
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);
            }
            finally
            {
                try
                {
                    s.close();
                }
                catch (IOException e)
                {
                }
                finally
                {
                }
            }
        }
    }
}
