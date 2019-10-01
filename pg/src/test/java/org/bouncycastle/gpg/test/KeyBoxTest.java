package org.bouncycastle.gpg.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.util.Iterator;

import junit.framework.TestCase;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.gpg.keybox.BlobType;
import org.bouncycastle.gpg.keybox.CertificateBlob;
import org.bouncycastle.gpg.keybox.FirstBlob;
import org.bouncycastle.gpg.keybox.KeyBlob;
import org.bouncycastle.gpg.keybox.KeyBox;
import org.bouncycastle.gpg.keybox.PublicKeyRingBlob;
import org.bouncycastle.gpg.keybox.bc.BcBlobVerifier;
import org.bouncycastle.gpg.keybox.bc.BcKeyBox;
import org.bouncycastle.gpg.keybox.jcajce.JcaKeyBoxBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class KeyBoxTest
    extends SimpleTest
{
    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new KeyBoxTest());
    }

    public String getName()
    {
        return "KeyBoxTest";
    }

    /**
     * Test loading a key store and extracting information.
     *
     * @throws Exception
     */
    public void testSuccessfulLoad()
        throws Exception
    {
        loadCheck(new BcKeyBox(KeyBoxTest.class.getResourceAsStream("/pgpdata/pubring.kbx")));
        loadCheck(new JcaKeyBoxBuilder().build(KeyBoxTest.class.getResourceAsStream("/pgpdata/pubring.kbx")));
    }

    private void loadCheck(KeyBox keyBox)
        throws Exception
    {

        FirstBlob firstBlob = keyBox.getFirstBlob();


        //
        // Check the first blob.
        //
        TestCase.assertEquals(BlobType.FIRST_BLOB, firstBlob.getType());
        TestCase.assertEquals("Version", 1, firstBlob.getVersion());
        TestCase.assertEquals("Header flags.", 2, firstBlob.getHeaderFlags());
        TestCase.assertEquals("Created at date.", 1526963333, firstBlob.getFileCreatedAt());
        TestCase.assertEquals("Last maintained date.", 1526963333, firstBlob.getLastMaintenanceRun());

        // Number of blobs.
        TestCase.assertEquals("Two material blobs.", 2, keyBox.getKeyBlobs().size());


        for (KeyBlob keyBlob : keyBox.getKeyBlobs())
        {

            switch (keyBlob.getType())
            {
            case X509_BLOB:
            {
                TestCase.assertEquals(2, keyBlob.getUserIds().size());
                TestCase.assertEquals(keyBlob.getNumberOfUserIDs(), keyBlob.getUserIds().size());

                // Self signed.
                TestCase.assertEquals("CN=Peggy Shippen", keyBlob.getUserIds().get(0).getUserIDAsString());
                TestCase.assertEquals("CN=Peggy Shippen", keyBlob.getUserIds().get(1).getUserIDAsString());

                // It can be successfully parsed into a certificate.


                byte[] certData = ((CertificateBlob)keyBlob).getEncodedCertificate();
                CertificateFactory factory = CertificateFactory.getInstance("X509");
                factory.generateCertificate(new ByteArrayInputStream(certData));

                TestCase.assertEquals(1, keyBlob.getKeyInformation().size());
                TestCase.assertEquals(20, keyBlob.getKeyInformation().get(0).getFingerprint().length);
                TestCase.assertNull(keyBlob.getKeyInformation().get(0).getKeyID());
            }
            break;


            case OPEN_PGP_BLOB:
                TestCase.assertEquals(1, keyBlob.getUserIds().size());
                TestCase.assertEquals(keyBlob.getNumberOfUserIDs(), keyBlob.getUserIds().size());
                TestCase.assertEquals("Walter Mitty <walter@mitty.local>", keyBlob.getUserIds().get(0).getUserIDAsString());

                //
                // It can be successfully parsed.
                //
                ((PublicKeyRingBlob)keyBlob).getPGPPublicKeyRing();

                TestCase.assertEquals(2, keyBlob.getKeyInformation().size());
                TestCase.assertEquals(20, keyBlob.getKeyInformation().get(0).getFingerprint().length);
                TestCase.assertNotNull(keyBlob.getKeyInformation().get(0).getKeyID());

                TestCase.assertEquals(20, keyBlob.getKeyInformation().get(1).getFingerprint().length);
                TestCase.assertNotNull(keyBlob.getKeyInformation().get(1).getKeyID());

                break;

            default:
                TestCase.fail("Unexpected blob type: " + keyBlob.getType());
            }
        }

    }

    /**
     * Test load kb with El Gamal keys in it.
     *
     * @throws Exception
     */
    public void testSanityElGamal()
        throws Exception
    {
        testSanityElGamal_verify(new BcKeyBox(KeyBoxTest.class.getResourceAsStream("/pgpdata/eg_pubring.kbx")));
        testSanityElGamal_verify(new JcaKeyBoxBuilder().setProvider("BC").build(KeyBoxTest.class.getResourceAsStream("/pgpdata/eg_pubring.kbx")));
    }

    private void testSanityElGamal_verify(KeyBox keyBox)
        throws Exception
    {
        FirstBlob firstBlob = keyBox.getFirstBlob();


        //
        // Check the first blob.
        //
        TestCase.assertEquals(BlobType.FIRST_BLOB, firstBlob.getType());
        TestCase.assertEquals("Version", 1, firstBlob.getVersion());
        TestCase.assertEquals("Header flags.", 2, firstBlob.getHeaderFlags());
        TestCase.assertEquals("Created at date.", 1527840866, firstBlob.getFileCreatedAt());
        TestCase.assertEquals("Last maintained date.", 1527840866, firstBlob.getLastMaintenanceRun());

        // Number of blobs.
        TestCase.assertEquals("One material blobs.", 1, keyBox.getKeyBlobs().size());

        TestCase.assertEquals("Pgp type", BlobType.OPEN_PGP_BLOB, keyBox.getKeyBlobs().get(0).getType());

        PublicKeyRingBlob pgkr = (PublicKeyRingBlob)keyBox.getKeyBlobs().get(0);
        PGPPublicKeyRing ring = pgkr.getPGPPublicKeyRing();

        TestCase.assertEquals("Must be DSA", PublicKeyAlgorithmTags.DSA, ring.getPublicKey().getAlgorithm());

        Iterator<PGPPublicKey> it = ring.getPublicKeys();
        it.next();
        TestCase.assertEquals("Must be ELGAMAL_ENCRYPT", PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, it.next().getAlgorithm());
    }


    /**
     * Induce a checksum failure in the first key block.
     *
     * @throws Exception
     */
    public void testInducedChecksumFailed()
        throws Exception
    {

        byte[] raw = Streams.readAll(KeyBoxTest.class.getResourceAsStream("/pgpdata/pubring.kbx"));

        raw[36] ^= 1; // Single bit error in first key block.


        // BC
        try
        {
            new KeyBox(raw, new BcKeyFingerprintCalculator(), new BcBlobVerifier());
            fail("Must have invalid checksum");
        }
        catch (IOException ioex)
        {
            isEquals("Blob with base offset of 32 has incorrect digest.", ioex.getMessage());
        }

        // JCA
        try
        {
            new JcaKeyBoxBuilder().setProvider("BC").build(raw);
            fail("Must have invalid checksum");
        }
        catch (IOException ioex)
        {
            isEquals("Blob with base offset of 32 has incorrect digest.", ioex.getMessage());
        }

    }


    public void testBrokenMagic()
        throws Exception
    {
        byte[] raw = Streams.readAll(KeyBoxTest.class.getResourceAsStream("/pgpdata/pubring.kbx"));

        raw[8] ^= 1; // Single bit error in magic number.

        // BC
        try
        {
            new KeyBox(raw, new BcKeyFingerprintCalculator(), new BcBlobVerifier());
            fail("Must have invalid magic");
        }
        catch (IOException ioex)
        {
            isEquals("Incorrect magic expecting 4b425866 but got 4a425866", ioex.getMessage());
        }


        // JCA
        try
        {
            new JcaKeyBoxBuilder().setProvider("BC").build(raw);
            fail("Must have invalid checksum");
        }
        catch (IOException ioex)
        {
            isEquals("Incorrect magic expecting 4b425866 but got 4a425866", ioex.getMessage());
        }
    }

    public void testNullSource()
        throws Exception
    {
        InputStream zulu = null;

        // BC
        try
        {
            new KeyBox(zulu, new BcKeyFingerprintCalculator(), new BcBlobVerifier());
            fail("Must fail.");
        }
        catch (IllegalArgumentException ioex)
        {
            isEquals("Cannot take get instance of null", ioex.getMessage());
        }

        // JCA
        try
        {
            new JcaKeyBoxBuilder().setProvider("BC").build(zulu);
            fail("Must fail.");
        }
        catch (IllegalArgumentException ioex)
        {
            isEquals("Cannot take get instance of null", ioex.getMessage());
        }

    }


    public void testNoFirstBlob()
        throws Exception
    {
        // BC
        try
        {
            new KeyBox(new byte[0], new BcKeyFingerprintCalculator(), new BcBlobVerifier());
            fail("Must fail.");
        }
        catch (IOException ioex)
        {
            isEquals("No first blob, is the source zero length?", ioex.getMessage());
        }

        // JCA
        try
        {
            new JcaKeyBoxBuilder().setProvider("BC").build(new byte[0]);
            fail("Must fail.");
        }
        catch (IOException ioex)
        {
            isEquals("No first blob, is the source zero length?", ioex.getMessage());
        }

    }

    public void testDoubleFirstBlob()
        throws Exception
    {
        // BC
        try
        {
            new KeyBox(KeyBoxTest.class.getResourceAsStream("/pgpdata/doublefirst.kbx"), new BcKeyFingerprintCalculator(), new BcBlobVerifier());
            fail("Must fail.");
        }
        catch (IOException ioex)
        {
            isEquals("Unexpected second 'FirstBlob', there should only be one FirstBlob at the start of the file.", ioex.getMessage());
        }


        // JCA
        try
        {
            new JcaKeyBoxBuilder().setProvider("BC").build(KeyBoxTest.class.getResourceAsStream("/pgpdata/doublefirst.kbx"));
            fail("Must fail.");
        }
        catch (IOException ioex)
        {
            isEquals("Unexpected second 'FirstBlob', there should only be one FirstBlob at the start of the file.", ioex.getMessage());
        }
    }

    public void testKeyBoxWithMD5Sanity()
        throws Exception
    {
        //
        // Expect no failure.
        //
        new BcKeyBox(KeyBoxTest.class.getResourceAsStream("/pgpdata/md5kbx.kbx"));
        new JcaKeyBoxBuilder().build(KeyBoxTest.class.getResourceAsStream("/pgpdata/md5kbx.kbx"));
    }

    public void testKeyBoxWithBrokenMD5()
        throws Exception
    {
        byte[] raw = Streams.readAll(KeyBoxTest.class.getResourceAsStream("/pgpdata/md5kbx.kbx"));

        raw[36] ^= 1; // Single bit error in first key block.

        // BC
        try
        {
            new KeyBox(raw, new BcKeyFingerprintCalculator(), new BcBlobVerifier());
            fail("Must have invalid checksum");
        }
        catch (IOException ioex)
        {
            isEquals("Blob with base offset of 32 has incorrect digest.", ioex.getMessage());
        }

        // JCA
        try
        {
            new JcaKeyBoxBuilder().setProvider("BC").build(raw);
            fail("Must have invalid checksum");
        }
        catch (IOException ioex)
        {
            isEquals("Blob with base offset of 32 has incorrect digest.", ioex.getMessage());
        }


    }


    public void performTest()
        throws Exception
    {
        testNoFirstBlob();
        testSanityElGamal();
        testKeyBoxWithBrokenMD5();
        testKeyBoxWithMD5Sanity();
        testDoubleFirstBlob();
        testNullSource();
        testBrokenMagic();
        testSuccessfulLoad();
        testInducedChecksumFailed();
    }


}
