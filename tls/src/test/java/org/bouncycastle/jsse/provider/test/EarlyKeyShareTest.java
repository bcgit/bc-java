package org.bouncycastle.jsse.provider.test;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.util.Vector;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import junit.framework.TestCase;
import org.bouncycastle.tls.ClientHello;
import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.HandshakeType;
import org.bouncycastle.tls.KeyShareEntry;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.TlsExtensionsUtils;

/**
 * What a BCJSSE client offers when nothing has been configured: X25519MLKEM768 leads the named
 * groups, and the first ClientHello carries a key share for it as well as for x25519, so a server
 * that supports the hybrid negotiates it without a HelloRetryRequest and one that does not falls
 * back to x25519 at no extra cost (NIST IR 8547 sec. 4.2 names the TLS 1.3 hybrids as the
 * near-term migration path).
 */
public class EarlyKeyShareTest
    extends TestCase
{
    public void testDefaultClientHelloOffersHybridFirstWithAKeyShare() throws Exception
    {
        ProviderUtils.setupHighPriority(false);

        SSLContext clientContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
        clientContext.init(null, null, null);

        SSLEngine clientEngine = clientContext.createSSLEngine();
        clientEngine.setUseClientMode(true);
        clientEngine.setEnabledProtocols(new String[]{ "TLSv1.3" });
        clientEngine.beginHandshake();

        ByteBuffer clientToServer = ByteBuffer.allocate(clientEngine.getSession().getPacketBufferSize());
        clientEngine.wrap(ByteBuffer.allocate(0), clientToServer);
        clientToServer.flip();

        byte[] record = new byte[clientToServer.remaining()];
        clientToServer.get(record);

        assertEquals("handshake record", ContentType.handshake, record[0] & 0xFF);
        assertEquals("ClientHello", HandshakeType.client_hello, record[5] & 0xFF);

        int messageLength = ((record[6] & 0xFF) << 16) | ((record[7] & 0xFF) << 8) | (record[8] & 0xFF);

        ClientHello clientHello = ClientHello.parse(new ByteArrayInputStream(record, 9, messageLength), null);

        int[] supportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(clientHello.getExtensions());
        assertNotNull("no supported_groups extension", supportedGroups);
        assertEquals("most preferred group", NamedGroup.getText(NamedGroup.X25519MLKEM768),
            NamedGroup.getText(supportedGroups[0]));
        assertEquals("second group", NamedGroup.getText(NamedGroup.x25519), NamedGroup.getText(supportedGroups[1]));

        Vector shares = TlsExtensionsUtils.getKeyShareClientHello(clientHello.getExtensions());
        assertNotNull("no key_share extension", shares);
        assertEquals("key_share count", 2, shares.size());
        assertEquals("first key_share", NamedGroup.getText(NamedGroup.X25519MLKEM768),
            NamedGroup.getText(((KeyShareEntry)shares.elementAt(0)).getNamedGroup()));
        assertEquals("second key_share", NamedGroup.getText(NamedGroup.x25519),
            NamedGroup.getText(((KeyShareEntry)shares.elementAt(1)).getNamedGroup()));
    }
}
