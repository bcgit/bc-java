package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsMAC;
import org.bouncycastle.tls.crypto.TlsMACOutputStream;
import org.bouncycastle.util.Arrays;

/**
 * Implements cookie generation/verification for a DTLS server as described in RFC 4347,
 * 4.2.1. Denial of Service Countermeasures.
 * <p/>
 * RFC 4347 4.2.1 additionally recommends changing the secret frequently. This class does not handle that
 * internally, so the instance should be replaced instead.
 * <p>
 * DTLS 1.2 and earlier only. DTLS 1.3 removed the HelloVerifyRequest and carries its cookie in a
 * HelloRetryRequest instead (RFC 9147 5.1), which is part of the handshake transcript and so needs the first
 * ClientHello's hash and the selected parameters stored in the cookie. This class does not implement that
 * exchange yet, so a server reached through it cannot negotiate DTLS 1.3: {@link DTLSServerProtocol} fails
 * such a handshake with an internal_error alert at the ServerHello rather than let the client abort it. A
 * server offering {@link ProtocolVersion#DTLSv13} therefore has to accept connections without this front end,
 * and without any stateless denial-of-service countermeasure, until a HelloRetryRequest cookie exchange is
 * added here.
 * </p>
 */
public class DTLSVerifier
{
    private final TlsCrypto crypto;
    private final byte[] macKey;

    public DTLSVerifier(TlsCrypto crypto)
    {
        this.crypto = crypto;
        this.macKey = new byte[32];
        crypto.getSecureRandom().nextBytes(macKey);
    }

    public DTLSRequest verifyRequest(byte[] clientID, byte[] data, int dataOff, int dataLen, DatagramSender sender)
    {
        try
        {
            int msgLen = DTLSRecordLayer.receiveClientHelloRecord(data, dataOff, dataLen);
            if (msgLen < 0)
            {
                return null;
            }

            int bodyLength = msgLen - DTLSReliableHandshake.MESSAGE_HEADER_LENGTH;
            if (bodyLength < 39) // Minimum (syntactically) valid DTLS ClientHello length
            {
                return null;
            }

            int msgOff = dataOff + DTLSRecordLayer.RECORD_HEADER_LENGTH;

            ByteArrayInputStream buf = DTLSReliableHandshake.receiveClientHelloMessage(data, msgOff, msgLen);
            if (buf == null)
            {
                return null;
            }

            ByteArrayOutputStream macInput = new ByteArrayOutputStream(bodyLength);
            ClientHello clientHello = ClientHello.parse(buf, macInput);
            if (clientHello == null)
            {
                return null;
            }

            long recordSeq = TlsUtils.readUint48(data, dataOff + 5);

            byte[] cookie = clientHello.getCookie();

            TlsMAC mac = crypto.createHMAC(MACAlgorithm.hmac_sha256);
            mac.setKey(macKey, 0, macKey.length);
            mac.update(clientID, 0, clientID.length);
            macInput.writeTo(new TlsMACOutputStream(mac));
            byte[] expectedCookie = mac.calculateMAC();

            if (Arrays.constantTimeAreEqual(expectedCookie, cookie))
            {
                byte[] message = TlsUtils.copyOfRangeExact(data, msgOff, msgOff + msgLen);

                return new DTLSRequest(recordSeq, message, clientHello);
            }

            DTLSReliableHandshake.sendHelloVerifyRequest(sender, recordSeq, expectedCookie);
        }
        catch (IOException e)
        {
            // Ignore
        }

        return null;
    }
}
