package org.bouncycastle.tls;

import java.io.IOException;

import junit.framework.TestCase;

/**
 * draft-ietf-tls-rfc9147bis: message_seq is a uint16 that MUST NOT wrap. The send side has to refuse the
 * 65537th message rather than let writeUint16 truncate it onto the sequence number of an earlier one.
 */
public class DTLSMessageSeqTest
    extends TestCase
{
    public void testLastMessageSeqIsStillSent() throws IOException
    {
        DTLS13HandshakeTestSupport support = new DTLS13HandshakeTestSupport();
        support.begin(500);

        support.setNextSendSeq(0xFFFF);
        support.sendMessage();
    }

    public void testMessageSeqWrapIsRefused() throws IOException
    {
        DTLS13HandshakeTestSupport support = new DTLS13HandshakeTestSupport();
        support.begin(500);

        support.setNextSendSeq(0x10000);
        try
        {
            support.sendMessage();
            fail("message_seq 65536 must not be sent");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.internal_error, e.getAlertDescription());
        }
    }
}
