package org.bouncycastle.jsse.provider.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Vector;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import junit.framework.TestCase;

import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.bouncycastle.util.Integers;

/**
 * The <code>org.bouncycastle.jsse.useNamedGroupsOrder</code> system property, which sets the
 * default for {@link BCSSLParameters#setUseNamedGroupsOrder(boolean)}: connections of an SSLContext
 * initialised while it is true default to having the server select the key share group by its own
 * named group order, while a value set on a connection's parameters still overrides the default
 * either way. It is read when the SSLContext is initialised, so a context initialised before the
 * property was set does not see it.
 * <p>
 * The client is a low-level {@link TlsClientProtocol} rather than a BCJSSE socket because that is
 * what exposes the negotiated group. It offers secp256r1 then x25519 (with a key share for
 * secp256r1 only) against a server whose named groups are x25519 then secp256r1, so which group
 * comes out says whose order was used: secp256r1 for the client's, x25519 for the server's.
 */
public class UseNamedGroupsOrderTest
    extends TestCase
{
    private static final String PROPERTY_NAME = "org.bouncycastle.jsse.useNamedGroupsOrder";

    private static final String HOST = "localhost";

    private static final int CLIENT_FIRST = NamedGroup.secp256r1;
    private static final int SERVER_FIRST = NamedGroup.x25519;

    private static final String[] SERVER_NAMED_GROUPS = new String[]{
        NamedGroup.getStandardName(SERVER_FIRST), NamedGroup.getStandardName(CLIENT_FIRST) };

    /** Leave the connection's useNamedGroupsOrder at the context's default. */
    private static final Boolean DEFAULT = null;

    protected void setUp()
    {
        ProviderUtils.setupLowPriority(false);
        System.clearProperty(PROPERTY_NAME);
    }

    protected void tearDown()
    {
        System.clearProperty(PROPERTY_NAME);
    }

    public void testPropertyUnset()
        throws Exception
    {
        SSLContext serverContext = createServerContext();

        assertFalse(getDefaultUseNamedGroupsOrder(serverContext));

        assertEquals(CLIENT_FIRST, negotiate(serverContext, DEFAULT));
        assertEquals(CLIENT_FIRST, negotiate(serverContext, Boolean.FALSE));
        assertEquals(SERVER_FIRST, negotiate(serverContext, Boolean.TRUE));
    }

    public void testPropertyFalse()
        throws Exception
    {
        System.setProperty(PROPERTY_NAME, "false");
        SSLContext serverContext = createServerContext();

        assertFalse(getDefaultUseNamedGroupsOrder(serverContext));

        assertEquals(CLIENT_FIRST, negotiate(serverContext, DEFAULT));
        assertEquals(SERVER_FIRST, negotiate(serverContext, Boolean.TRUE));
    }

    public void testPropertyTrue()
        throws Exception
    {
        System.setProperty(PROPERTY_NAME, "true");
        SSLContext serverContext = createServerContext();

        assertTrue(getDefaultUseNamedGroupsOrder(serverContext));

        assertEquals(SERVER_FIRST, negotiate(serverContext, DEFAULT));
        assertEquals(SERVER_FIRST, negotiate(serverContext, Boolean.TRUE));

        // the property is only the default; the connection's own setting still wins
        assertEquals(CLIENT_FIRST, negotiate(serverContext, Boolean.FALSE));
    }

    /**
     * Read when the SSLContext is initialised: a context from before the property was set keeps
     * the old default while one initialised afterwards takes the new one.
     */
    public void testPropertyReadPerContext()
        throws Exception
    {
        SSLContext before = createServerContext();

        System.setProperty(PROPERTY_NAME, "true");

        SSLContext after = createServerContext();

        assertFalse(getDefaultUseNamedGroupsOrder(before));
        assertTrue(getDefaultUseNamedGroupsOrder(after));

        assertEquals(CLIENT_FIRST, negotiate(before, DEFAULT));
        assertEquals(SERVER_FIRST, negotiate(after, DEFAULT));

        System.clearProperty(PROPERTY_NAME);

        // and clearing it again does not reach into the context that already read it
        assertTrue(getDefaultUseNamedGroupsOrder(after));
        assertEquals(SERVER_FIRST, negotiate(after, DEFAULT));
    }

    private static SSLContext createServerContext()
        throws Exception
    {
        KeyStore[] credential = NamedGroupTestUtil.createRSACredential();

        return NamedGroupTestUtil.createServerContext(ProviderUtils.getProviderBCJSSE(), credential[0]);
    }

    /**
     * The default a fresh socket from the context reports, as an application would see it.
     */
    private static boolean getDefaultUseNamedGroupsOrder(SSLContext context)
        throws IOException
    {
        BCSSLSocket socket = (BCSSLSocket)context.getSocketFactory().createSocket();
        try
        {
            return socket.getParameters().getUseNamedGroupsOrder();
        }
        finally
        {
            ((Socket)socket).close();
        }
    }

    /**
     * One TLS 1.3 handshake against a server socket from serverContext, returning the group the
     * server selected.
     *
     * @param useNamedGroupsOrder the value to set on the accepted socket's parameters, or null to
     *                            leave the context's default in place.
     */
    private static int negotiate(SSLContext serverContext, Boolean useNamedGroupsOrder)
        throws Exception
    {
        SSLServerSocketFactory serverFact = serverContext.getServerSocketFactory();
        SSLServerSocket sSock = (SSLServerSocket)serverFact.createServerSocket(0);
        try
        {
            sSock.setEnabledProtocols(new String[]{ "TLSv1.3" });

            final Exception[] serverFailure = new Exception[1];
            Thread serverThread = startEchoServer(sSock, useNamedGroupsOrder, serverFailure);

            GroupOrderClient client = new GroupOrderClient();

            Socket socket = new Socket(HOST, sSock.getLocalPort());
            try
            {
                TlsClientProtocol protocol = new TlsClientProtocol(socket.getInputStream(),
                    socket.getOutputStream());
                protocol.connect(client);

                OutputStream output = protocol.getOutputStream();
                output.write('!');
                output.flush();

                assertEquals('!', protocol.getInputStream().read());

                protocol.close();
            }
            finally
            {
                socket.close();
            }

            serverThread.join(30000);

            if (null != serverFailure[0])
            {
                throw serverFailure[0];
            }

            return client.getNegotiatedGroup();
        }
        finally
        {
            sSock.close();
        }
    }

    /**
     * Accepts one connection, applies the named groups (and useNamedGroupsOrder, when given) to it,
     * and echoes a byte, which is enough to drive the handshake to completion.
     */
    private static Thread startEchoServer(final SSLServerSocket serverSocket, final Boolean useNamedGroupsOrder,
        final Exception[] serverFailure)
    {
        Thread serverThread = new Thread(new Runnable()
        {
            public void run()
            {
                SSLSocket socket = null;
                try
                {
                    socket = (SSLSocket)serverSocket.accept();
                    socket.setUseClientMode(false);

                    BCSSLSocket bcSocket = (BCSSLSocket)socket;
                    BCSSLParameters bcParams = bcSocket.getParameters();
                    bcParams.setNamedGroups(SERVER_NAMED_GROUPS);
                    if (null != useNamedGroupsOrder)
                    {
                        bcParams.setUseNamedGroupsOrder(useNamedGroupsOrder.booleanValue());
                    }
                    bcSocket.setParameters(bcParams);

                    InputStream input = socket.getInputStream();
                    OutputStream output = socket.getOutputStream();

                    int b = input.read();
                    output.write(b);
                    output.flush();
                }
                catch (Exception e)
                {
                    serverFailure[0] = e;
                }
                finally
                {
                    if (null != socket)
                    {
                        try
                        {
                            socket.close();
                        }
                        catch (IOException e)
                        {
                            // ignore
                        }
                    }
                }
            }
        }, "UseNamedGroupsOrderTest-server");

        serverThread.setDaemon(true);
        serverThread.start();

        return serverThread;
    }

    /**
     * Offers secp256r1 then x25519 with an early key share for secp256r1 only, so a server that
     * prefers its own order has to retry for x25519, and records the group that was negotiated.
     */
    private static class GroupOrderClient
        extends DefaultTlsClient
    {
        private int negotiatedGroup = -1;

        GroupOrderClient()
            throws GeneralSecurityException
        {
            super(new JcaTlsCryptoProvider().setProvider(ProviderUtils.PROVIDER_NAME_BC)
                .create(new SecureRandom()));
        }

        int getNegotiatedGroup()
        {
            return negotiatedGroup;
        }

        protected ProtocolVersion[] getSupportedVersions()
        {
            return ProtocolVersion.TLSv13.only();
        }

        protected Vector getSupportedGroups(Vector namedGroupRoles)
        {
            Vector supportedGroups = new Vector();
            supportedGroups.addElement(Integers.valueOf(CLIENT_FIRST));
            supportedGroups.addElement(Integers.valueOf(SERVER_FIRST));
            return supportedGroups;
        }

        public Vector getEarlyKeyShareGroups()
        {
            return TlsUtils.vectorOfOne(Integers.valueOf(CLIENT_FIRST));
        }

        public void notifyHandshakeComplete()
            throws IOException
        {
            super.notifyHandshakeComplete();

            negotiatedGroup = context.getSecurityParametersConnection().getNegotiatedGroup();
        }

        public TlsAuthentication getAuthentication()
        {
            return new TlsAuthentication()
            {
                public void notifyServerCertificate(TlsServerCertificate serverCertificate)
                {
                    // the credential is the test's own; what is under test is the group selection
                }

                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
                {
                    return null;
                }
            };
        }
    }
}
