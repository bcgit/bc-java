package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

public final class SessionParameters
{
    public static final class Builder
    {
        private int cipherSuite = -1;
        private short compressionAlgorithm = -1;
        private Certificate localCertificate = null;
        private TlsSecret masterSecret = null;
        private ProtocolVersion negotiatedVersion;
        private Certificate peerCertificate = null;
        private byte[] pskIdentity = null;
        private byte[] srpIdentity = null;
        private byte[] encodedServerExtensions = null;
        private boolean extendedMasterSecret = false;

        public Builder()
        {
        }

        public SessionParameters build()
        {
            validate(this.cipherSuite >= 0, "cipherSuite");
            validate(this.compressionAlgorithm >= 0, "compressionAlgorithm");
            validate(this.masterSecret != null, "masterSecret");
            return new SessionParameters(cipherSuite, compressionAlgorithm, localCertificate, masterSecret,
                negotiatedVersion, peerCertificate, pskIdentity, srpIdentity, encodedServerExtensions,
                extendedMasterSecret);
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

        public Builder setExtendedMasterSecret(boolean extendedMasterSecret)
        {
            this.extendedMasterSecret = extendedMasterSecret;
            return this;
        }

        public Builder setLocalCertificate(Certificate localCertificate)
        {
            this.localCertificate = localCertificate;
            return this;
        }

        public Builder setMasterSecret(TlsSecret masterSecret)
        {
            this.masterSecret = masterSecret;
            return this;
        }

        public Builder setNegotiatedVersion(ProtocolVersion negotiatedVersion)
        {
            this.negotiatedVersion = negotiatedVersion;
            return this;
        }

        public Builder setPeerCertificate(Certificate peerCertificate)
        {
            this.peerCertificate = peerCertificate;
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

        public Builder setServerExtensions(Hashtable serverExtensions) throws IOException
        {
            if (serverExtensions == null || serverExtensions.isEmpty())
            {
                encodedServerExtensions = null;
            }
            else
            {
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                TlsProtocol.writeExtensions(buf, serverExtensions);
                encodedServerExtensions = buf.toByteArray();
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
    private Certificate localCertificate;
    private TlsSecret masterSecret;
    private ProtocolVersion negotiatedVersion;
    private Certificate peerCertificate;
    private byte[] pskIdentity = null;
    private byte[] srpIdentity = null;
    private byte[] encodedServerExtensions;
    private boolean extendedMasterSecret;

    private SessionParameters(int cipherSuite, short compressionAlgorithm, Certificate localCertificate,
        TlsSecret masterSecret, ProtocolVersion negotiatedVersion, Certificate peerCertificate, byte[] pskIdentity,
        byte[] srpIdentity, byte[] encodedServerExtensions, boolean extendedMasterSecret)
    {
        this.cipherSuite = cipherSuite;
        this.compressionAlgorithm = compressionAlgorithm;
        this.localCertificate = localCertificate;
        this.masterSecret = masterSecret;
        this.negotiatedVersion = negotiatedVersion;
        this.peerCertificate = peerCertificate;
        this.pskIdentity = Arrays.clone(pskIdentity);
        this.srpIdentity = Arrays.clone(srpIdentity);
        this.encodedServerExtensions = encodedServerExtensions;
        this.extendedMasterSecret = extendedMasterSecret;
    }

    public void clear()
    {
        if (this.masterSecret != null)
        {
            this.masterSecret.destroy();
        }
    }

    public SessionParameters copy()
    {
        return new SessionParameters(cipherSuite, compressionAlgorithm, localCertificate, masterSecret,
            negotiatedVersion, peerCertificate, pskIdentity, srpIdentity, encodedServerExtensions,
            extendedMasterSecret);
    }

    public int getCipherSuite()
    {
        return cipherSuite;
    }

    public short getCompressionAlgorithm()
    {
        return compressionAlgorithm;
    }

    public Certificate getLocalCertificate()
    {
        return localCertificate;
    }

    public TlsSecret getMasterSecret()
    {
        return masterSecret;
    }

    public ProtocolVersion getNegotiatedVersion()
    {
        return negotiatedVersion;
    }

    public Certificate getPeerCertificate()
    {
        return peerCertificate;
    }

    public byte[] getPSKIdentity()
    {
        return pskIdentity;
    }

    public byte[] getSRPIdentity()
    {
        return srpIdentity;
    }

    public boolean isExtendedMasterSecret()
    {
        return extendedMasterSecret;
    }

    public Hashtable readServerExtensions() throws IOException
    {
        if (encodedServerExtensions == null)
        {
            return null;
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(encodedServerExtensions);
        return TlsProtocol.readExtensions(buf);
    }
}
