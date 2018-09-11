package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.util.Arrays;

public final class SessionParameters
{
    public static final class Builder
    {
        private int cipherSuite = -1;
        private short compressionAlgorithm = -1;
        private byte[] masterSecret = null;
        private Certificate peerCertificate = null;
        private byte[] pskIdentity = null;
        private byte[] srpIdentity = null;
        private byte[] encodedPeerExtensions = null;

        public Builder()
        {
        }

        public SessionParameters build()
        {
            validate(this.cipherSuite >= 0, "cipherSuite");
            validate(this.compressionAlgorithm >= 0, "compressionAlgorithm");
            validate(this.masterSecret != null, "masterSecret");
            return new SessionParameters(cipherSuite, compressionAlgorithm, masterSecret, peerCertificate, pskIdentity,
                srpIdentity, encodedPeerExtensions);
        }

        public Builder setCipherSuite(int cipherSuite)
        {
            this.cipherSuite = cipherSuite;
            return this;
        }

        public Builder setCompressionAlgorithm(short compressionAlgorithm)
        {
            this.compressionAlgorithm = compressionAlgorithm;
            return this;
        }

        public Builder setMasterSecret(byte[] masterSecret)
        {
            this.masterSecret = masterSecret;
            return this;
        }

        public Builder setPeerCertificate(Certificate peerCertificate)
        {
            this.peerCertificate = peerCertificate;
            return this;
        }

        /**
         * @deprecated Use {@link #setPSKIdentity(byte[])}
         */
        public Builder setPskIdentity(byte[] pskIdentity)
        {
            this.pskIdentity = pskIdentity;
            return this;
        }

        public Builder setPSKIdentity(byte[] pskIdentity)
        {
            this.pskIdentity = pskIdentity;
            return this;
        }

        public Builder setSRPIdentity(byte[] srpIdentity)
        {
            this.srpIdentity = srpIdentity;
            return this;
        }

        public Builder setPeerExtensions(Hashtable peerExtensions) throws IOException
        {
            if (peerExtensions == null)
            {
                encodedPeerExtensions = null;
            }
            else
            {
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                TlsProtocol.writeExtensions(buf, peerExtensions);
                encodedPeerExtensions = buf.toByteArray();
            }
            return this;
        }

        private void validate(boolean condition, String parameter)
        {
            if (!condition)
            {
                throw new IllegalStateException("Required session parameter '" + parameter + "' not configured");
            }
        }
    }

    private int cipherSuite;
    private short compressionAlgorithm;
    private byte[] masterSecret;
    private Certificate peerCertificate;
    private byte[] pskIdentity = null;
    private byte[] srpIdentity = null;
    private byte[] encodedPeerExtensions;

    private SessionParameters(int cipherSuite, short compressionAlgorithm, byte[] masterSecret,
        Certificate peerCertificate, byte[] pskIdentity, byte[] srpIdentity, byte[] encodedPeerExtensions)
    {
        this.cipherSuite = cipherSuite;
        this.compressionAlgorithm = compressionAlgorithm;
        this.masterSecret = Arrays.clone(masterSecret);
        this.peerCertificate = peerCertificate;
        this.pskIdentity = Arrays.clone(pskIdentity);
        this.srpIdentity = Arrays.clone(srpIdentity);
        this.encodedPeerExtensions = encodedPeerExtensions;
    }

    public void clear()
    {
        if (this.masterSecret != null)
        {
            Arrays.fill(this.masterSecret, (byte)0);
        }
    }

    public SessionParameters copy()
    {
        return new SessionParameters(cipherSuite, compressionAlgorithm, masterSecret, peerCertificate, pskIdentity,
            srpIdentity, encodedPeerExtensions);
    }

    public int getCipherSuite()
    {
        return cipherSuite;
    }

    public short getCompressionAlgorithm()
    {
        return compressionAlgorithm;
    }

    public byte[] getMasterSecret()
    {
        return masterSecret;
    }

    public Certificate getPeerCertificate()
    {
        return peerCertificate;
    }

    /**
     * @deprecated Use {@link #getPSKIdentity()}
     */
    public byte[] getPskIdentity()
    {
        return pskIdentity;
    }

    public byte[] getPSKIdentity()
    {
        return pskIdentity;
    }

    public byte[] getSRPIdentity()
    {
        return srpIdentity;
    }

    public Hashtable readPeerExtensions() throws IOException
    {
        if (encodedPeerExtensions == null)
        {
            return null;
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(encodedPeerExtensions);
        return TlsProtocol.readExtensions(buf);
    }
}
