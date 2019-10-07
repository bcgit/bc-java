package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

class SSL3Utils
{
    private static final byte[] SSL_CLIENT = {0x43, 0x4C, 0x4E, 0x54};
    private static final byte[] SSL_SERVER = {0x53, 0x52, 0x56, 0x52};

    private static final byte IPAD_BYTE = (byte)0x36;
    private static final byte OPAD_BYTE = (byte)0x5C;

    private static final byte[] IPAD = genPad(IPAD_BYTE, 48);
    private static final byte[] OPAD = genPad(OPAD_BYTE, 48);

    static byte[] calculateVerifyData(TlsHandshakeHash handshakeHash, boolean isServer)
    {
        TlsHash prf = handshakeHash.forkPRFHash();
        byte[] sslSender = isServer ? SSL_SERVER : SSL_CLIENT;
        prf.update(sslSender, 0, sslSender.length);
        return prf.calculateHash();
    }

    static void completeCombinedHash(TlsContext context, TlsHash md5, TlsHash sha1)
    {
        TlsSecret masterSecret = context.getSecurityParametersHandshake().getMasterSecret();
        byte[] master_secret = context.getCrypto().adoptSecret(masterSecret).extract();

        completeHash(master_secret, md5, 48);
        completeHash(master_secret, sha1, 40);
    }

    private static void completeHash(byte[] master_secret, TlsHash hash, int padLength)
    {
        hash.update(master_secret, 0, master_secret.length);
        hash.update(IPAD, 0, padLength);

        byte[] tmp = hash.calculateHash();

        hash.update(master_secret, 0, master_secret.length);
        hash.update(OPAD, 0, padLength);
        hash.update(tmp, 0, tmp.length);
    }

    private static byte[] genPad(byte b, int count)
    {
        byte[] padding = new byte[count];
        Arrays.fill(padding, b);
        return padding;
    }

    static byte[] readEncryptedPMS(InputStream input) throws IOException
    {
        return Streams.readAll(input);
    }

    static void writeEncryptedPMS(byte[] encryptedPMS, OutputStream output) throws IOException
    {
        output.write(encryptedPMS);
    }
}
