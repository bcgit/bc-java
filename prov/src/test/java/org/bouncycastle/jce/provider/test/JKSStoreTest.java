package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Security;

import org.bouncycastle.jcajce.provider.keystore.util.AdaptingKeyStoreSpi;
import org.bouncycastle.jcajce.provider.keystore.util.JKSKeyStoreSpi;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

public class JKSStoreTest
    extends SimpleTest
{
    public String getName()
    {
        return "JKSStore";
    }

    public void performTest()
        throws Exception
    {
        testLoadTruncatedStore();
        testLoadTruncatedStoreThroughKeyStore();
        testCertificateLengthOutOfRange();
    }

    /**
     * A certificate entry whose declared length is negative or larger than the store must be
     * refused before anything is allocated for it. The FIPS/IFIPS compatibility stores read JKS
     * with no property set, and with a null password the checksum is not checked at all, so the
     * length is attacker-controlled on both paths.
     */
    private void testCertificateLengthOutOfRange()
        throws Exception
    {
        char[] password = "changeit".toCharArray();
        int[] lengths = new int[]{ Integer.MAX_VALUE, -1, Integer.MIN_VALUE, 17 };
        String[] storeTypes = new String[]{ "FIPS", "FIPS-DEF", "IFIPS", "IFIPS-DEF" };

        for (int i = 0; i != lengths.length; i++)
        {
            byte[] store = hostileStore(lengths[i], password);

            implLoadTruncatedStore(store, null);
            implLoadTruncatedStore(store, password);

            for (int j = 0; j != storeTypes.length; j++)
            {
                implLoadHostileStore(storeTypes[j], store, null, lengths[i]);
                implLoadHostileStore(storeTypes[j], store, password, lengths[i]);
            }
        }

        // the store is otherwise well formed: the right checksum under the password is accepted
        // up to the length check, and a wrong password is still refused by the checksum.
        KeyStore ks = KeyStore.getInstance("FIPS", "BC");
        try
        {
            ks.load(new ByteArrayInputStream(hostileStore(Integer.MAX_VALUE, password)), "wrong".toCharArray());
            fail("store loaded under the wrong password");
        }
        catch (IOException e)
        {
            isEquals("password incorrect or store tampered with", e.getMessage());
        }
    }

    private void implLoadHostileStore(String storeType, byte[] store, char[] password, int length)
        throws Exception
    {
        KeyStore ks = KeyStore.getInstance(storeType, "BC");

        try
        {
            ks.load(new ByteArrayInputStream(store), password);

            fail(storeType + ": certificate length " + length + " accepted");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    /**
     * A version 1 JKS store holding one certificate entry with the given declared length followed
     * by 16 bytes of data, and a valid checksum for password.
     */
    private static byte[] hostileStore(int certLength, char[] password)
        throws IOException
    {
        java.io.ByteArrayOutputStream bOut = new java.io.ByteArrayOutputStream();
        java.io.DataOutputStream dOut = new java.io.DataOutputStream(bOut);

        dOut.writeInt(0xfeedfeed);
        dOut.writeInt(1);
        dOut.writeInt(1);
        dOut.writeInt(2);
        dOut.writeUTF("cert");
        dOut.writeLong(0L);
        dOut.writeInt(certLength);
        dOut.write(new byte[16]);
        dOut.flush();

        byte[] body = bOut.toByteArray();

        org.bouncycastle.crypto.digests.SHA1Digest sha1 = new org.bouncycastle.crypto.digests.SHA1Digest();
        for (int i = 0; i < password.length; ++i)
        {
            sha1.update((byte)(password[i] >> 8));
            sha1.update((byte)password[i]);
        }
        byte[] whitener = org.bouncycastle.util.Strings.toByteArray("Mighty Aphrodite");
        sha1.update(whitener, 0, whitener.length);
        sha1.update(body, 0, body.length);

        byte[] checksum = new byte[sha1.getDigestSize()];
        sha1.doFinal(checksum, 0);

        return Arrays.concatenate(body, checksum);
    }

    private void testLoadTruncatedStore()
        throws Exception
    {
        // shorter than the checksum alone, and shorter than the header plus the checksum
        int[] lengths = new int[]{ 0, 4, 19, 31 };

        for (int i = 0; i != lengths.length; i++)
        {
            byte[] store = Arrays.copyOfRange(PKCS12StoreTest.JKS_Store, 0, lengths[i]);

            implLoadTruncatedStore(store, null);
            implLoadTruncatedStore(store, PKCS12StoreTest.JKS_TEST_PWD);
        }
    }

    private void implLoadTruncatedStore(byte[] store, char[] password)
        throws Exception
    {
        JKSKeyStoreSpi jksStore = new JKSKeyStoreSpi(new BCJcaJceHelper());

        try
        {
            jksStore.engineLoad(new ByteArrayInputStream(store), password);

            fail("truncated store of " + store.length + " bytes accepted");
        }
        catch (EOFException e)
        {
            // expected
        }
    }

    /**
     * The JKS store is reached through the compatibility probe in AdaptingKeyStoreSpi, so a
     * truncated store has to leave KeyStore.load() by way of its declared IOException rather
     * than an ArrayIndexOutOfBoundsException (github #2451).
     */
    private void testLoadTruncatedStoreThroughKeyStore()
        throws Exception
    {
        String compatValue = System.getProperty(AdaptingKeyStoreSpi.COMPAT_OVERRIDE);

        System.setProperty(AdaptingKeyStoreSpi.COMPAT_OVERRIDE, "true");

        try
        {
            int[] lengths = new int[]{ 0, 4, 19, 31 };

            for (int i = 0; i != lengths.length; i++)
            {
                byte[] store = Arrays.copyOfRange(PKCS12StoreTest.JKS_Store, 0, lengths[i]);

                KeyStore ks = KeyStore.getInstance("PKCS12", "BC");

                try
                {
                    ks.load(new ByteArrayInputStream(store), PKCS12StoreTest.JKS_TEST_PWD);

                    fail("truncated store of " + store.length + " bytes accepted");
                }
                catch (IOException e)
                {
                    // expected
                }
            }
        }
        finally
        {
            if (compatValue == null)
            {
                System.getProperties().remove(AdaptingKeyStoreSpi.COMPAT_OVERRIDE);
            }
            else
            {
                System.setProperty(AdaptingKeyStoreSpi.COMPAT_OVERRIDE, compatValue);
            }
        }
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new JKSStoreTest());
    }
}
