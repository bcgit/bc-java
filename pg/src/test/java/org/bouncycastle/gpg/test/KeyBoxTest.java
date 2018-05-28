package org.bouncycastle.gpg.test;

import java.io.IOException;
import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.gpg.keybox.BlobType;
import org.bouncycastle.gpg.keybox.CertificateBlob;
import org.bouncycastle.gpg.keybox.FirstBlob;
import org.bouncycastle.gpg.keybox.KeyBlob;
import org.bouncycastle.gpg.keybox.KeyBox;
import org.bouncycastle.gpg.keybox.PublicKeyRingBlob;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class KeyBoxTest
    extends SimpleTest
{
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
        KeyBox keyBox = new KeyBox(KeyBoxTest.class.getResourceAsStream("/pgpdata/pubring.kbx"), new BcKeyFingerprintCalculator());
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
            System.out.println(new String(keyBlob.getUserIds().get(0).getUserID()));


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
                ((CertificateBlob)keyBlob).getEncodedCertificate();

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
     * Induce a checksum failure in the first key block.
     *
     * @throws Exception
     */
    public void testInducedChecksumFailed()
        throws Exception
    {

        byte[] raw = Streams.readAll(KeyBoxTest.class.getResourceAsStream("/pgpdata/pubring.kbx"));

        raw[36] ^= 1; // Single bit error in first key block.

        try
        {
            new KeyBox(raw, new BcKeyFingerprintCalculator());
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
        testSuccessfulLoad();
        testInducedChecksumFailed();
    }


    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new KeyBoxTest());
    }

}
