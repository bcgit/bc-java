package org.bouncycastle.jcajce.provider.keystore.util;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.jcajce.provider.util.DigestFactory;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

/**
 * Implements a certificate only JKS key store.
 */
public class JKSKeyStoreSpi
    extends KeyStoreSpi
{
    private static final String NOT_IMPLEMENTED_MESSAGE = "BC JKS store is read-only and only supports certificate entries";

    private final Hashtable<String, BCJKSTrustedCertEntry> certificateEntries = new Hashtable<String, BCJKSTrustedCertEntry>();
    private JcaJceHelper helper;

    public JKSKeyStoreSpi(JcaJceHelper helper)
    {
        this.helper = helper;
    }

    public boolean engineProbe(InputStream stream)
        throws IOException
    {
        DataInputStream storeStream;
        if (stream instanceof DataInputStream)
        {
            storeStream = (DataInputStream)stream;
        }
        else
        {
            storeStream = new DataInputStream(stream);
        }

        int magic = storeStream.readInt();
        int storeVersion = storeStream.readInt();
        return magic == (int)0x0000feedfeedL && (storeVersion == 1 || storeVersion == 2);
    }

    public Key engineGetKey(String alias, char[] password)
        throws NoSuchAlgorithmException, UnrecoverableKeyException
    {
        return null;  // by definition
    }

    public Certificate[] engineGetCertificateChain(String alias)
    {
        return null;  // by definition
    }

    public Certificate engineGetCertificate(String alias)
    {
        synchronized (certificateEntries)
        {
            BCJKSTrustedCertEntry ent = (BCJKSTrustedCertEntry)certificateEntries.get(alias);
            if (ent != null)
            {
                return ent.cert;
            }
        }
        return null;
    }

    public Date engineGetCreationDate(String alias)
    {
        synchronized (certificateEntries)
        {
            BCJKSTrustedCertEntry ent = (BCJKSTrustedCertEntry)certificateEntries.get(alias);
            if (ent != null)
            {
                return ent.date;
            }
        }
        return null;
    }

    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
        throws KeyStoreException
    {
        throw new KeyStoreException(NOT_IMPLEMENTED_MESSAGE);
    }

    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
        throws KeyStoreException
    {
        throw new KeyStoreException(NOT_IMPLEMENTED_MESSAGE);
    }

    public void engineSetCertificateEntry(String alias, Certificate cert)
        throws KeyStoreException
    {
        throw new KeyStoreException(NOT_IMPLEMENTED_MESSAGE);
    }

    public void engineDeleteEntry(String alias)
        throws KeyStoreException
    {
        throw new KeyStoreException(NOT_IMPLEMENTED_MESSAGE);
    }

    public Enumeration<String> engineAliases()
    {
        synchronized (certificateEntries)
        {
            return certificateEntries.keys();
        }
    }

    public boolean engineContainsAlias(String alias)
    {
        if (alias == null)
        {
            throw new NullPointerException("alias value is null");
        }

        synchronized (certificateEntries)
        {
            return certificateEntries.containsKey(alias);
        }
    }

    public int engineSize()
    {
        return certificateEntries.size();
    }

    public boolean engineIsKeyEntry(String alias)
    {
        return false;    // by definition
    }

    public boolean engineIsCertificateEntry(String alias)
    {
        synchronized (certificateEntries)
        {
            return certificateEntries.containsKey(alias);
        }
    }

    public String engineGetCertificateAlias(Certificate cert)
    {
        synchronized (certificateEntries)
        {
            for (Enumeration it = certificateEntries.keys(); it.hasMoreElements(); )
            {
                String key = (String)it.nextElement();
                BCJKSTrustedCertEntry entry = (BCJKSTrustedCertEntry)certificateEntries.get(key);
                if (entry.cert.equals(cert))
                {
                    return key;
                }
            }
            return null;
        }
    }

    public void engineStore(OutputStream stream, char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException
    {
        throw new IOException(NOT_IMPLEMENTED_MESSAGE);
    }

    public void engineLoad(InputStream stream, char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException
    {
        if (stream == null)
        {
            return;
        }

        ErasableByteStream storeStream = validateStream(stream, password);

        synchronized (certificateEntries)
        {
            try
            {
                DataInputStream dIn = new DataInputStream(storeStream);

                int magic = dIn.readInt();
                int storeVersion = dIn.readInt();
                if (magic == (int)0x0000feedfeedL)
                {
                    CertificateFactory certFact = null;
                    Hashtable certFactories = null;

                    switch (storeVersion)
                    {
                    case 1:  // all certs X.509
                        certFact = createCertFactory("X.509");
                        break;
                    case 2:  // provision for format in store.
                        certFactories = new Hashtable();
                        break;
                    default:
                        throw new IllegalStateException("unable to discern store version");
                    }

                    int numEntries = dIn.readInt();
                    for (int t = 0; t < numEntries; t++)
                    {
                        int tag = dIn.readInt();
                        switch (tag)
                        {
                        case 1: // we can't process keys
                            throw new IOException(NOT_IMPLEMENTED_MESSAGE);
                        case 2: // certificate
                            String alias = dIn.readUTF();
                            Date date = new Date(dIn.readLong());

                            if (storeVersion == 2)
                            {
                                String certFormat = dIn.readUTF();
                                if (certFactories.containsKey(certFormat))
                                {
                                    certFact = (CertificateFactory)certFactories.get(certFormat);
                                }
                                else
                                {
                                    certFact = createCertFactory(certFormat);
                                    certFactories.put(certFormat, certFact);
                                }
                            }

                            int l = dIn.readInt();
                            byte[] certData = new byte[l];
                            dIn.readFully(certData);

                            ErasableByteStream certStream = new ErasableByteStream(certData, 0, certData.length);
                            Certificate cert;
                            try
                            {
                                cert = certFact.generateCertificate(certStream);

                                if (certStream.available() != 0)
                                {
                                    throw new IOException("password incorrect or store tampered with");
                                }
                            }
                            finally
                            {
                                certStream.erase();
                            }

                            certificateEntries.put(alias, new BCJKSTrustedCertEntry(date, cert));
                            break;
                        default:
                            throw new IllegalStateException("unable to discern entry type");
                        }
                    }
                }

                if (storeStream.available() != 0)
                {
                    throw new IOException("password incorrect or store tampered with");
                }
            }
            finally
            {
                storeStream.erase();
            }
        }
    }

    private CertificateFactory createCertFactory(String certFormat)
        throws CertificateException
    {
        if (helper != null)
        {
            try
            {
                return helper.createCertificateFactory(certFormat);
            }
            catch (NoSuchProviderException e)
            {
                throw new CertificateException(e.toString());
            }
        }
        else
        {
            return CertificateFactory.getInstance(certFormat);
        }
    }

    /**
     * Process password updates the digest with the password.
     *
     * @param digest   The digest instance.
     * @param password The password.
     */
    private void addPassword(Digest digest, char[] password)
        throws IOException
    {
        for (int i = 0; i < password.length; ++i)
        {
            digest.update((byte)(password[i] >> 8));
            digest.update((byte)password[i]);
        }

        //
        // This "Mighty Aphrodite" string goes all the way back to the
        // first java betas in the mid 90's, why who knows? But see
        // https://cryptosense.com/mighty-aphrodite-dark-secrets-of-the-java-keystore/
        //
        digest.update(Strings.toByteArray("Mighty Aphrodite"), 0, 16);
    }

    /**
     * Validate password takes the checksum of the store and will either.
     * 1. If password is null, load the store into memory, return the result.
     * 2. If password is not null, load the store into memory, test the checksum, and if successful return
     * a new input stream instance of the store.
     * 3. Fail if there is a password and an invalid checksum.
     *
     * @param inputStream The input stream.
     * @param password    the password.
     * @return Either the passed in input stream or a new input stream.
     * @throws IOException
     */
    private ErasableByteStream validateStream(InputStream inputStream, char[] password)
        throws IOException
    {
        Digest checksumCalculator = DigestFactory.getDigest("SHA-1");
        byte[] rawStore = Streams.readAll(inputStream);

        if (password != null)
        {
            addPassword(checksumCalculator, password);
            checksumCalculator.update(rawStore, 0, rawStore.length - checksumCalculator.getDigestSize());

            byte[] checksum = new byte[checksumCalculator.getDigestSize()];

            checksumCalculator.doFinal(checksum, 0);

            byte[] streamChecksum = new byte[checksum.length];
            System.arraycopy(rawStore, rawStore.length - checksum.length, streamChecksum, 0, checksum.length);

            if (!Arrays.constantTimeAreEqual(checksum, streamChecksum))
            {
                Arrays.fill(rawStore, (byte)0);
                throw new IOException("password incorrect or store tampered with");
            }

            return new ErasableByteStream(rawStore, 0, rawStore.length - checksum.length);
        }

        return new ErasableByteStream(rawStore, 0, rawStore.length - checksumCalculator.getDigestSize());
    }

    /**
     * BCJKSTrustedCertEntry is a internal container for the certificate entry.
     */
    static final class BCJKSTrustedCertEntry
    {
        final Date date;
        final Certificate cert;

        public BCJKSTrustedCertEntry(Date date, Certificate cert)
        {
            this.date = date;
            this.cert = cert;
        }
    }

    private static final class ErasableByteStream
        extends ByteArrayInputStream
    {
        public ErasableByteStream(byte[] buf, int offSet, int length)
        {
            super(buf, offSet, length);
        }

        public void erase()
        {
            // this will also erase the checksum from memory.
            Arrays.fill(buf, (byte)0);
        }
    }


}

