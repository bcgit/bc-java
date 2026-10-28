package org.bouncycastle.tls.test;

import java.io.ByteArrayInputStream;
import java.util.Vector;

import junit.framework.TestCase;
import org.bouncycastle.tls.ClientHello;
import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.HandshakeType;
import org.bouncycastle.tls.KeyShareEntry;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.TlsClient;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

/**
 * Which groups a TLS 1.3 client sends key shares for in its first ClientHello (RFC 8446 4.2.8).
 * A client offering X25519MLKEM768 sends a share for it, so a server that supports the hybrid
 * settles on it without a HelloRetryRequest, plus one classical share as the fallback for a
 * server that does not; the shares keep supported_groups order.
 */
public class Tls13EarlyKeyShareTest
    extends TestCase
{
    public void testHybridAndClassicalSharesFollowSupportedGroupsOrder() throws Exception
    {
        MockTlsHybridClient client = new MockTlsHybridClient(new BcTlsCrypto(), null);
        client.setNamedGroups(new int[]{ NamedGroup.x25519, NamedGroup.X25519MLKEM768, NamedGroup.secp256r1 });

        assertKeyShareGroups(new int[]{ NamedGroup.x25519, NamedGroup.X25519MLKEM768 }, client);

        client = new MockTlsHybridClient(new BcTlsCrypto(), null);
        client.setNamedGroups(new int[]{ NamedGroup.X25519MLKEM768, NamedGroup.x25519, NamedGroup.secp256r1 });

        assertKeyShareGroups(new int[]{ NamedGroup.X25519MLKEM768, NamedGroup.x25519 }, client);
    }

    public void testSecp256r1IsTheFallbackWithoutX25519() throws Exception
    {
        MockTlsHybridClient client = new MockTlsHybridClient(new BcTlsCrypto(), null);
        client.setNamedGroups(new int[]{ NamedGroup.secp256r1, NamedGroup.X25519MLKEM768, NamedGroup.secp384r1 });

        assertKeyShareGroups(new int[]{ NamedGroup.secp256r1, NamedGroup.X25519MLKEM768 }, client);
    }

    public void testHybridOnlyClientSendsTheHybridShare() throws Exception
    {
        // MockTlsHybridClient offers SecP256r1MLKEM768 first; the X25519 hybrid is still the share sent
        assertKeyShareGroups(new int[]{ NamedGroup.X25519MLKEM768 }, new MockTlsHybridClient(new BcTlsCrypto(), null));
    }

    public void testClassicalClientSendsX25519Share() throws Exception
    {
        assertKeyShareGroups(new int[]{ NamedGroup.x25519 }, new MockTlsClient(null));
    }

    private static void assertKeyShareGroups(int[] expected, TlsClient client) throws Exception
    {
        Vector shares = clientHelloKeyShares(client);

        assertEquals("key_share count", expected.length, shares.size());
        for (int i = 0; i < expected.length; ++i)
        {
            assertEquals("key_share " + i, NamedGroup.getText(expected[i]),
                NamedGroup.getText(((KeyShareEntry)shares.elementAt(i)).getNamedGroup()));
        }
    }

    /**
     * Drive the client in non-blocking mode so its ClientHello can be read back without a server.
     */
    private static Vector clientHelloKeyShares(TlsClient client) throws Exception
    {
        TlsClientProtocol protocol = new TlsClientProtocol();
        protocol.connect(client);

        byte[] record = new byte[protocol.getAvailableOutputBytes()];
        protocol.readOutput(record, 0, record.length);

        assertEquals("handshake record", ContentType.handshake, record[0] & 0xFF);
        assertEquals("ClientHello", HandshakeType.client_hello, record[5] & 0xFF);

        int messageLength = ((record[6] & 0xFF) << 16) | ((record[7] & 0xFF) << 8) | (record[8] & 0xFF);

        ClientHello clientHello = ClientHello.parse(new ByteArrayInputStream(record, 9, messageLength), null);

        Vector shares = TlsExtensionsUtils.getKeyShareClientHello(clientHello.getExtensions());
        assertNotNull("no key_share extension", shares);
        return shares;
    }
}
