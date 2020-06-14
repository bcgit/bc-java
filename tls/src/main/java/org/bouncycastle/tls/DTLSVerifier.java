package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsMAC;
import org.bouncycastle.tls.crypto.TlsMACOutputStream;
import org.bouncycastle.util.Arrays;

public class DTLSVerifier
{
    private static TlsMAC createCookieMAC(TlsCrypto crypto)
    {
        TlsMAC mac = crypto.createHMAC(MACAlgorithm.hmac_sha256);

        byte[] secret = new byte[mac.getMacLength()];
        crypto.getSecureRandom().nextBytes(secret);

        mac.setKey(secret, 0, secret.length);

        return mac;
    }

    private final TlsMAC cookieMAC;
    private final TlsMACOutputStream cookieMACOutputStream;

    public DTLSVerifier(TlsCrypto crypto)
    {
        this.cookieMAC = createCookieMAC(crypto);
        this.cookieMACOutputStream = new TlsMACOutputStream(cookieMAC);
    }

    public synchronized DTLSRequest verifyRequest(byte[] clientID, byte[] data, int dataOff, int dataLen,
        DatagramSender sender)
    {
        boolean resetCookieMAC = true;

        try
        {
            cookieMAC.update(clientID, 0, clientID.length);

            DTLSRequest request = DTLSReliableHandshake.readClientRequest(data, dataOff, dataLen, cookieMACOutputStream);
            if (null != request)
            {
                byte[] expectedCookie = cookieMAC.calculateMAC();
                resetCookieMAC = false;

                // TODO Consider stricter HelloVerifyRequest protocol
//                switch (request.getMessageSeq())
//                {
//                case 0:
//                {
//                    DTLSReliableHandshake.sendHelloVerifyRequest(sender, request.getRecordSeq(), expectedCookie);
//                    break;
//                }
//                case 1:
//                {
//                    if (Arrays.constantTimeAreEqual(expectedCookie, request.getClientHello().getCookie()))
//                    {
//                        return request;
//                    }
//                    break;
//                }
//                }

                if (Arrays.constantTimeAreEqual(expectedCookie, request.getClientHello().getCookie()))
                {
                    return request;
                }

                DTLSReliableHandshake.sendHelloVerifyRequest(sender, request.getRecordSeq(), expectedCookie);
            }
        }
        catch (IOException e)
        {
            // Ignore
        }
        finally
        {
            if (resetCookieMAC)
            {
                cookieMAC.reset();
            }
        }

        return null;
    }
}
