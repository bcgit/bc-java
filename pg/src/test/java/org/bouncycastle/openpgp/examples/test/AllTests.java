package org.bouncycastle.openpgp.examples.test;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.openpgp.examples.ClearSignedFileProcessor;
import org.bouncycastle.openpgp.examples.DSAElGamalKeyRingGenerator;
import org.bouncycastle.openpgp.examples.KeyBasedFileProcessor;
import org.bouncycastle.openpgp.examples.KeyBasedLargeFileProcessor;
import org.bouncycastle.openpgp.examples.PBEFileProcessor;
import org.bouncycastle.openpgp.examples.RSAKeyPairGenerator;
import org.bouncycastle.openpgp.examples.SignedFileProcessor;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;

public class AllTests
    extends TestCase
{
    byte[] clearSignedPublicKey = Base64.decode(
           "mQELBEQh2+wBCAD26kte0hO6flr7Y2aetpPYutHY4qsmDPy+GwmmqVeCDkX+"
         + "r1g7DuFbMhVeu0NkKDnVl7GsJ9VarYsFYyqu0NzLa9XS2qlTIkmJV+2/xKa1"
         + "tzjn18fT/cnAWL88ZLCOWUr241aPVhLuIc6vpHnySpEMkCh4rvMaimnTrKwO"
         + "42kgeDGd5cXfs4J4ovRcTbc4hmU2BRVsRjiYMZWWx0kkyL2zDVyaJSs4yVX7"
         + "Jm4/LSR1uC/wDT0IJJuZT/gQPCMJNMEsVCziRgYkAxQK3OWojPSuv4rXpyd4"
         + "Gvo6IbvyTgIskfpSkCnQtORNLIudQSuK7pW+LkL62N+ohuKdMvdxauOnAAYp"
         + "tBNnZ2dnZ2dnZyA8Z2dnQGdnZ2c+iQE2BBMBAgAgBQJEIdvsAhsDBgsJCAcD"
         + "AgQVAggDBBYCAwECHgECF4AACgkQ4M/Ier3f9xagdAf/fbKWBjLQM8xR7JkR"
         + "P4ri8YKOQPhK+VrddGUD59/wzVnvaGyl9MZE7TXFUeniQq5iXKnm22EQbYch"
         + "v2Jcxyt2H9yptpzyh4tP6tEHl1C887p2J4qe7F2ATua9CzVGwXQSUbKtj2fg"
         + "UZP5SsNp25guhPiZdtkf2sHMeiotmykFErzqGMrvOAUThrO63GiYsRk4hF6r"
         + "cQ01d+EUVpY/sBcCxgNyOiB7a84sDtrxnX5BTEZDTEj8LvuEyEV3TMUuAjx1"
         + "7Eyd+9JtKzwV4v3hlTaWOvGro9nPS7YaPuG+RtufzXCUJPbPfTjTvtGOqvEz"
         + "oztls8tuWA0OGHba9XfX9rfgorACAAM=");

    String crOnlyMessage =
        "\r"
      + " hello world!\r"
      + "\r"
      + "- dash\r";

    String nlOnlyMessage =
          "\n"
        + " hello world!\n"
        + "\n"
        + "- dash\n";

    String crNlMessage =
          "\r\n"
        + " hello world!\r\n"
        + "\r\n"
        + "- dash\r\n";

    String crNlMessageTrailingWhiteSpace =
          "\r\n"
        + " hello world! \t\r\n"
        + "\r\n"
        + "\r\n";

    String crOnlySignedMessage =
        "-----BEGIN PGP SIGNED MESSAGE-----\r"
      + "Hash: SHA256\r"
      + "\r"
      + "\r"
      + " hello world!\r"
      + "\r"
      + "- - dash\r"
      + "-----BEGIN PGP SIGNATURE-----\r"
      + "Version: GnuPG v1.4.2.1 (GNU/Linux)\r"
      + "\r"
      + "iQEVAwUBRCNS8+DPyHq93/cWAQi6SwgAj3ItmSLr/sd/ixAQLW7/12jzEjfNmFDt\r"
      + "WOZpJFmXj0fnMzTrOILVnbxHv2Ru+U8Y1K6nhzFSR7d28n31/XGgFtdohDEaFJpx\r"
      + "Fl+KvASKIonnpEDjFJsPIvT1/G/eCPalwO9IuxaIthmKj0z44SO1VQtmNKxdLAfK\r"
      + "+xTnXGawXS1WUE4CQGPM45mIGSqXcYrLtJkAg3jtRa8YRUn2d7b2BtmWH+jVaVuC\r"
      + "hNrXYv7iHFOu25yRWhUQJisvdC13D/gKIPRvARXPgPhAC2kovIy6VS8tDoyG6Hm5\r"
      + "dMgLEGhmqsgaetVq1ZIuBZj5S4j2apBJCDpF6GBfpBOfwIZs0Tpmlw==\r"
      + "=84Nd\r"
      + "-----END PGP SIGNATURE-----\r";


    String nlOnlySignedMessage =
          "-----BEGIN PGP SIGNED MESSAGE-----\n"
        + "Hash: SHA256\n"
        + "\n"
        + "\n"
        + " hello world!\n"
        + "\n"
        + "- - dash\n"
        + "-----BEGIN PGP SIGNATURE-----\n"
        + "Version: GnuPG v1.4.2.1 (GNU/Linux)\n"
        + "\n"
        + "iQEVAwUBRCNS8+DPyHq93/cWAQi6SwgAj3ItmSLr/sd/ixAQLW7/12jzEjfNmFDt\n"
        + "WOZpJFmXj0fnMzTrOILVnbxHv2Ru+U8Y1K6nhzFSR7d28n31/XGgFtdohDEaFJpx\n"
        + "Fl+KvASKIonnpEDjFJsPIvT1/G/eCPalwO9IuxaIthmKj0z44SO1VQtmNKxdLAfK\n"
        + "+xTnXGawXS1WUE4CQGPM45mIGSqXcYrLtJkAg3jtRa8YRUn2d7b2BtmWH+jVaVuC\n"
        + "hNrXYv7iHFOu25yRWhUQJisvdC13D/gKIPRvARXPgPhAC2kovIy6VS8tDoyG6Hm5\n"
        + "dMgLEGhmqsgaetVq1ZIuBZj5S4j2apBJCDpF6GBfpBOfwIZs0Tpmlw==\n"
        + "=84Nd\n"
        + "-----END PGP SIGNATURE-----\n";

    String crNlSignedMessage =
        "-----BEGIN PGP SIGNED MESSAGE-----\r\n"
      + "Hash: SHA256\r\n"
      + "\r\n"
      + "\r\n"
      + " hello world!\r\n"
      + "\r\n"
      + "- - dash\r\n"
      + "-----BEGIN PGP SIGNATURE-----\r\n"
      + "Version: GnuPG v1.4.2.1 (GNU/Linux)\r\n"
      + "\r\n"
      + "iQEVAwUBRCNS8+DPyHq93/cWAQi6SwgAj3ItmSLr/sd/ixAQLW7/12jzEjfNmFDt\r\n"
      + "WOZpJFmXj0fnMzTrOILVnbxHv2Ru+U8Y1K6nhzFSR7d28n31/XGgFtdohDEaFJpx\r\n"
      + "Fl+KvASKIonnpEDjFJsPIvT1/G/eCPalwO9IuxaIthmKj0z44SO1VQtmNKxdLAfK\r\n"
      + "+xTnXGawXS1WUE4CQGPM45mIGSqXcYrLtJkAg3jtRa8YRUn2d7b2BtmWH+jVaVuC\r\n"
      + "hNrXYv7iHFOu25yRWhUQJisvdC13D/gKIPRvARXPgPhAC2kovIy6VS8tDoyG6Hm5\r\n"
      + "dMgLEGhmqsgaetVq1ZIuBZj5S4j2apBJCDpF6GBfpBOfwIZs0Tpmlw==\r\n"
      + "=84Nd\r"
      + "-----END PGP SIGNATURE-----\r\n";

    String crNlSignedMessageTrailingWhiteSpace =
        "-----BEGIN PGP SIGNED MESSAGE-----\r\n"
      + "Hash: SHA256\r\n"
      + "\r\n"
      + "\r\n"
      + " hello world! \t\r\n"
      + "\r\n"
      + "- - dash\r\n"
      + "-----BEGIN PGP SIGNATURE-----\r\n"
      + "Version: GnuPG v1.4.2.1 (GNU/Linux)\r\n"
      + "\r\n"
      + "iQEVAwUBRCNS8+DPyHq93/cWAQi6SwgAj3ItmSLr/sd/ixAQLW7/12jzEjfNmFDt\r\n"
      + "WOZpJFmXj0fnMzTrOILVnbxHv2Ru+U8Y1K6nhzFSR7d28n31/XGgFtdohDEaFJpx\r\n"
      + "Fl+KvASKIonnpEDjFJsPIvT1/G/eCPalwO9IuxaIthmKj0z44SO1VQtmNKxdLAfK\r\n"
      + "+xTnXGawXS1WUE4CQGPM45mIGSqXcYrLtJkAg3jtRa8YRUn2d7b2BtmWH+jVaVuC\r\n"
      + "hNrXYv7iHFOu25yRWhUQJisvdC13D/gKIPRvARXPgPhAC2kovIy6VS8tDoyG6Hm5\r\n"
      + "dMgLEGhmqsgaetVq1ZIuBZj5S4j2apBJCDpF6GBfpBOfwIZs0Tpmlw==\r\n"
      + "=84Nd\r"
      + "-----END PGP SIGNATURE-----\r\n";

    private PrintStream _oldOut;
    private PrintStream _oldErr;
    
    private ByteArrayOutputStream _currentOut;
    private ByteArrayOutputStream _currentErr;

    public void setUp()
       throws Exception
    {
         _oldOut = System.out;
         _oldErr = System.err;
         _currentOut = new ByteArrayOutputStream();
         _currentErr = new ByteArrayOutputStream();
         
         System.setOut(new PrintStream(_currentOut));
         System.setErr(new PrintStream(_currentErr));
    }
    
    public void tearDown()
    {
        System.setOut(_oldOut);
        System.setErr(_oldErr);
    }

    public void testRSAKeyGeneration() 
        throws Exception
    {   
        RSAKeyPairGenerator.main(new String[] { "test", "password" });

        createSmallTestInput();
        createLargeTestInput();
        
        checkSigning("bpg");
        checkKeyBasedEncryption("bpg");
        checkLargeKeyBasedEncryption("bpg");
        
        RSAKeyPairGenerator.main(new String[] { "-a", "test", "password" });
        
        checkSigning("asc");
        checkKeyBasedEncryption("asc");
        checkLargeKeyBasedEncryption("asc");
    }
    
    public void testDSAElGamaleKeyGeneration() 
        throws Exception
    {   
        DSAElGamalKeyRingGenerator.main(new String[] { "test", "password" });
    
        createSmallTestInput();
        createLargeTestInput();
        
        checkSigning("bpg");
        checkKeyBasedEncryption("bpg");
        checkLargeKeyBasedEncryption("bpg");
        
        DSAElGamalKeyRingGenerator.main(new String[] { "-a", "test", "password" });
        
        checkSigning("asc");
        checkKeyBasedEncryption("asc");
        checkLargeKeyBasedEncryption("asc");
    }

    public void testPBEEncryption() 
        throws Exception
    {
        createTestData("hello world!", "test.txt");

        _currentErr.reset();
        
        PBEFileProcessor.main(new String[]{"-e", "test.txt", "password"});
        
        PBEFileProcessor.main(new String[]{"-d", "test.txt.bpg", "password"});
        
        assertEquals("no message integrity check", getLine(_currentErr));
        
        PBEFileProcessor.main(new String[]{"-e", "-i", "test.txt", "password"});
        
        PBEFileProcessor.main(new String[]{"-d", "test.txt.bpg", "password"});
        
        assertEquals("message integrity check passed", getLine(_currentErr));
        
        PBEFileProcessor.main(new String[]{"-e", "-ai", "test.txt", "password"});
        
        PBEFileProcessor.main(new String[]{"-d", "test.txt.asc", "password"});
        
        assertEquals("message integrity check passed", getLine(_currentErr));
    }

    public void testClearSigned()
        throws Exception
    {
        createTestFile(clearSignedPublicKey, "pub.bpg");

        checkClearSignedVerify(nlOnlySignedMessage);
        checkClearSignedVerify(crOnlySignedMessage);
        checkClearSignedVerify(crNlSignedMessage);
        checkClearSignedVerify(crNlSignedMessageTrailingWhiteSpace);

        ClearSignedFileProcessor.main(new String[] { "-v", "test.txt.asc", "pub.bpg" });

        RSAKeyPairGenerator.main(new String[] { "test", "password" });

        checkClearSigned(crOnlyMessage);
        checkClearSigned(nlOnlyMessage);
        checkClearSigned(crNlMessage);
        checkClearSigned(crNlMessageTrailingWhiteSpace);
    }

    public void testClearSignedBogusInput()
        throws Exception
    {
        createTestFile(clearSignedPublicKey, "test.txt");

        RSAKeyPairGenerator.main(new String[] { "test", "password" });

        ClearSignedFileProcessor.main(new String[]{"-s", "test.txt", "secret.bpg", "password"});
    }

    public void testClearSignedSingleLine()
        throws Exception
    {
        createTestData("This is a test payload!" + Strings.lineSeparator(), "test.txt");
        createTestData("This is a test payload!" + Strings.lineSeparator(), "test.bak");

        RSAKeyPairGenerator.main(new String[] { "test", "password" });

        ClearSignedFileProcessor.main(new String[]{"-s", "test.txt", "secret.bpg", "password"});
        ClearSignedFileProcessor.main(new String[]{"-v", "test.txt.asc", "pub.bpg"});

        compareFile("test.bak", "test.txt");
    }

    private void checkClearSignedVerify(String message)
        throws Exception
    {
        createTestData(message, "test.txt.asc");

        ClearSignedFileProcessor.main(new String[]{"-v", "test.txt.asc", "pub.bpg"});
    }

    private void compareFile(String file1, String file2)
        throws Exception
    {
        byte[] data1 = getFileContents(file1);
        byte[] data2 = getFileContents(file2);

        assertTrue(Arrays.areEqual(data1, data2));
    }

    private byte[] getFileContents(String name)
        throws IOException
    {
        FileInputStream fs = new FileInputStream(name);
        byte[] contents = Streams.readAll(fs);
        fs.close();
        return contents;
    }

    private void checkClearSigned(String message)
        throws Exception
    {
        createTestData(message, "test.txt");

        ClearSignedFileProcessor.main(new String[] { "-s", "test.txt", "secret.bpg", "password" });
        ClearSignedFileProcessor.main(new String[] { "-v", "test.txt.asc", "pub.bpg" });
    }

    private void checkSigning(String type)
        throws Exception
    {
        _currentOut.reset();
        
        SignedFileProcessor.main(new String[] { "-s", "test.txt", "secret." + type, "password" });
        
        SignedFileProcessor.main(new String[] { "-v", "test.txt.bpg", "pub." + type });
        
        assertEquals("signature verified.", getLine(_currentOut));
        
        SignedFileProcessor.main(new String[] { "-s", "-a", "test.txt", "secret." + type, "password" });
        
        SignedFileProcessor.main(new String[] { "-v", "test.txt.asc", "pub." + type });
        
        assertEquals("signature verified.", getLine(_currentOut));
    }

    private void checkKeyBasedEncryption(String type)
        throws Exception
    {
        _currentErr.reset();

        KeyBasedFileProcessor.main(new String[] { "-e", "test.txt", "pub." + type });

        KeyBasedFileProcessor.main(new String[] { "-d", "test.txt.bpg", "secret." + type, "password" });

        assertEquals("no message integrity check", getLine(_currentErr));

        KeyBasedFileProcessor.main(new String[] { "-e", "-i", "test.txt", "pub." + type });

        KeyBasedFileProcessor.main(new String[] { "-d", "test.txt.bpg", "secret." + type, "password" });

        assertEquals("message integrity check passed", getLine(_currentErr));

        KeyBasedFileProcessor.main(new String[] { "-e", "-ai", "test.txt", "pub." + type });

        KeyBasedFileProcessor.main(new String[] { "-d", "test.txt.asc", "secret." + type, "password" });

        assertEquals("message integrity check passed", getLine(_currentErr));
    }

    private void checkLargeKeyBasedEncryption(String type)
        throws Exception
    {
        _currentErr.reset();
        
        KeyBasedLargeFileProcessor.main(new String[] { "-e", "large.txt", "pub." + type });
        
        KeyBasedLargeFileProcessor.main(new String[] { "-d", "large.txt.bpg", "secret." + type, "password" });
        
        assertEquals("no message integrity check", getLine(_currentErr));
        
        KeyBasedLargeFileProcessor.main(new String[] { "-e", "-i", "large.txt", "pub." + type });
        
        KeyBasedLargeFileProcessor.main(new String[] { "-d", "large.txt.bpg", "secret." + type, "password" });
        
        assertEquals("message integrity check passed", getLine(_currentErr));
        
        KeyBasedLargeFileProcessor.main(new String[] { "-e", "-ai", "large.txt", "pub." + type });
        
        KeyBasedLargeFileProcessor.main(new String[] { "-d", "large.txt.asc", "secret." + type, "password" });
        
        assertEquals("message integrity check passed", getLine(_currentErr));
    }
    
    private void createSmallTestInput() 
        throws IOException
    {
        BufferedWriter bfOut = new BufferedWriter(new FileWriter("test.txt"));
        
        bfOut.write("hello world!");
        bfOut.newLine();
        
        bfOut.close();
    }
    
    private void createLargeTestInput() 
        throws IOException
    {
        BufferedWriter bfOut = new BufferedWriter(new FileWriter("large.txt"));
        
        for (int i = 0; i != 2000; i++)
        {
            bfOut.write("hello world!");
            bfOut.newLine();
        }
        
        bfOut.close();
    }

    private void createTestData(String testData, String name)
        throws IOException
    {
        BufferedWriter bfOut = new BufferedWriter(new FileWriter(name));

        bfOut.write(testData);

        bfOut.close();
    }

    private void createTestFile(byte[] keyData, String name)
        throws IOException
    {
        FileOutputStream fOut = new FileOutputStream(name);

        fOut.write(keyData);

        fOut.close();
    }

    private String getLine(
        ByteArrayOutputStream out) 
        throws IOException
    {
        BufferedReader bRd = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(out.toByteArray())));
        
        out.reset();
        
        return bRd.readLine();
    }
    
    public static void main (String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("OpenPGP Example Tests");
        
        suite.addTestSuite(AllTests.class);
        
        return suite;
    }
}
