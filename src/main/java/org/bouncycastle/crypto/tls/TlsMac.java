package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * A generic TLS MAC implementation, acting as an HMAC based on some underlying Digest.
 */
public class TlsMac
{
    protected TlsContext context;
    protected byte[] secret;
    protected Mac mac;

    /**
     * Generate a new instance of an TlsMac.
     * 
     * @param context the TLS client context
     * @param digest The digest to use.
     * @param key_block A byte-array where the key for this mac is located.
     * @param offset The number of bytes to skip, before the key starts in the buffer.
     * @param len The length of the key.
     */
    public TlsMac(TlsContext context, Digest digest, byte[] key_block, int offset, int len)
    {
        this.context = context;

        KeyParameter param = new KeyParameter(key_block, offset, len);

        this.secret = Arrays.clone(param.getKey());

        if (context.getServerVersion().isSSL())
        {
            this.mac = new SSL3Mac(digest);
        }
        else
        {
            this.mac = new HMac(digest);
        }

        this.mac.init(param);
    }

    /**
     * @return the MAC write secret
     */
    public byte[] getMACSecret()
    {
	return this.secret;
    }

    /**
     * @return The Keysize of the mac.
     */
    public int getSize()
    {
        return mac.getMacSize();
    }

    /**
     * Calculate the MAC for some given data.

     * @param type The message type of the message.
     * @param message A byte-buffer containing the message.
     * @param offset The number of bytes to skip, before the message starts.
     * @param len The length of the message.
     * @return A new byte-buffer containing the MAC value.
     */
    public byte[] calculateMac(long seqNo, short type, byte[] message, int offset, int len)
    {
        ProtocolVersion serverVersion = context.getServerVersion();
        boolean isSSL = serverVersion.isSSL();

        ByteArrayOutputStream bosMac = new ByteArrayOutputStream(isSSL ? 11 : 13);
        try
        {
            TlsUtils.writeUint64(seqNo, bosMac);
            TlsUtils.writeUint8(type, bosMac);

            if (!isSSL)
            {
                TlsUtils.writeVersion(serverVersion, bosMac);
            }

            TlsUtils.writeUint16(len, bosMac);
        }
        catch (IOException e)
        {
            // This should never happen
            throw new IllegalStateException("Internal error during mac calculation");
        }

        byte[] macHeader = bosMac.toByteArray();
        mac.update(macHeader, 0, macHeader.length);
        mac.update(message, offset, len);

        byte[] result = new byte[mac.getMacSize()];
        mac.doFinal(result, 0);
        return result;
    }

    public byte[] calculateMacConstantTime(long seqNo, short type, byte[] message, int offset, int len, int fullLength, byte[] dummyData)
    {
        // Actual MAC only calculated on 'len' bytes
        byte[] result = calculateMac(seqNo, type, message, offset, len);

        // ...but ensure a constant number of complete digest blocks are processed (per 'fullLength')
        if (!context.getServerVersion().isSSL())
        {
            // TODO Currently all TLS digests use a block size of 64, a suffix (length field) of 8, and padding (1+)
            int db = 64, ds = 8;

            int L1 = 13 + fullLength;
            int L2 = 13 + len;

            // How many extra full blocks do we need to calculate?
            int extra = ((L1 + ds) / db) - ((L2 + ds) / db);

            while (--extra >= 0)
            {
                mac.update(dummyData, 0, db);
            }
    
            // One more byte in case the implementation is "lazy" about processing blocks
            mac.update(dummyData[0]);
            mac.reset();
        }

        return result;
    }
}
