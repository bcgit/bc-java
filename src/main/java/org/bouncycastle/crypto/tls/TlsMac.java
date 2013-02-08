package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * A generic TLS MAC implementation, which can be used with any kind of Digest to act as
 * an HMAC.
 */
public class TlsMac
{
    protected TlsClientContext context;
    protected long seqNo;
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
    public TlsMac(TlsClientContext context, Digest digest, byte[] key_block, int offset, int len)
    {
        this.context = context;
        this.seqNo = 0;

        KeyParameter param = new KeyParameter(key_block, offset, len);

        this.secret = Arrays.clone(param.getKey());

        boolean isTls = context.getServerVersion().getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();

        if (isTls)
        {
            this.mac = new HMac(digest);
        }
        else
        {
            this.mac = new SSL3Mac(digest);
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
	 * @return the current write sequence number
	 */
	public long getSequenceNumber()
	{
		return this.seqNo;
	}

	/**
	 * Increment the current write sequence number
	 */
	public void incSequenceNumber()
	{
		this.seqNo++;
	}

    /**
     * @return The Keysize of the mac.
     */
    public int getSize()
    {
        return mac.getMacSize();
    }

    /**
     * Calculate the mac for some given data.
     * <p/>
     * TlsMac will keep track of the sequence number internally.
     * 
     * @param type The message type of the message.
     * @param message A byte-buffer containing the message.
     * @param offset The number of bytes to skip, before the message starts.
     * @param len The length of the message.
     * @return A new byte-buffer containing the mac value.
     */
    public byte[] calculateMac(short type, byte[] message, int offset, int len)
    {
        ProtocolVersion serverVersion = context.getServerVersion();
        boolean isTls = serverVersion.getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();

        ByteArrayOutputStream bosMac = new ByteArrayOutputStream(isTls ? 13 : 11);
        try
        {
            TlsUtils.writeUint64(seqNo++, bosMac);
            TlsUtils.writeUint8(type, bosMac);

            if (isTls)
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

    public byte[] calculateMacConstantTime(short type, byte[] message, int offset, int len, int fullLength, byte[] dummyData)
    {
        // Actual MAC only calculated on 'len' bytes
        byte[] result = calculateMac(type, message, offset, len);

        ProtocolVersion serverVersion = context.getServerVersion();
        boolean isTls = serverVersion.getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();

        // ...but ensure a constant number of complete digest blocks are processed (per 'fullLength')
        if (isTls)
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
