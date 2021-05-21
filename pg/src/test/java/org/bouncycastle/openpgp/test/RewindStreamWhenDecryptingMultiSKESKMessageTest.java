package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class RewindStreamWhenDecryptingMultiSKESKMessageTest
    extends SimpleTest
{

    private static final byte[] message = Strings.toByteArray("Hello World!\n");

    // pgpMessage was symmetrically encrypted using "password1" and "password2".
    // As the "password2" SKESK comes after "password1", but decryption of the
    // "password1" SKESK would result in a session key that looks okay, decryption
    // would commence and then fail when the checksum check fails.
    // After that the "password2" SKESK would be decrypted with "password2" which results
    // in the correct session key, but the encryption stream was already advanced, resulting
    // in a PGPDataViolationException or EOFException.
    // This has been fixed and this test verifies the now correct behavior.
    // Note that GnuPG < 2.3 also fails to decrypt the pgpMessage correctly.
    public void performTest()
        throws Exception
    {
        String pgpMessage = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: BCPG v1.68\n" +
            "\n" +
            "jC4ECQMCtL4bq5btiMJgL6wPT4kDozGheHZa1fmAUpp3CIBeLXw4B3IUZ05QSPRF\n" +
            "jC4ECQMC5nZ8aoh9uYpgtDeGdkTLP+obVSiMvs99ibpcFm60vJY7feYNTiSk2StJ\n" +
            "0kgB9vDAT0vUdXz1sPTEv2YIK2zeNyoA7pD9BDd68VgFVj61vSQ6Ovf6Uidv2v0M\n" +
            "5cfawfKpjRn0Ku3JEzDv3TuYioRWzuzxptc=\n" +
            "=9QAC\n" +
            "-----END PGP MESSAGE-----\n";

        byte[] decrypted = decrypt(Strings.toByteArray(pgpMessage), "password2");
        if (!Arrays.equals(message, decrypted))
        {
            throw new Exception("Decryption unsuccessful.");
        }
    }

    public static byte[] decrypt(byte[] ciphertext, String password)
        throws IOException, PGPException
    {
        InputStream stream = PGPUtil.getDecoderStream(new ByteArrayInputStream(ciphertext));
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(stream);
        Object o = objectFactory.nextObject();
        if (o instanceof PGPEncryptedDataList)
        {
            PGPEncryptedDataList dataList = (PGPEncryptedDataList)o;
            Iterator<PGPEncryptedData> iterator = dataList.iterator();
            while (iterator.hasNext())
            {
                PGPEncryptedData data = (PGPEncryptedData)iterator.next();
                if (data instanceof PGPPBEEncryptedData)
                {
                    PGPPBEEncryptedData pbeData = (PGPPBEEncryptedData)data;
                    try
                    {
                        PBEDataDecryptorFactory decryptorFactory = new BcPBEDataDecryptorFactory(password.toCharArray(), new BcPGPDigestCalculatorProvider());
                        InputStream decryptionStream = pbeData.getDataStream(decryptorFactory);
                        byte[] decrypted = decryptIntern(decryptionStream);
                        return decrypted;
                    }
                    catch (PGPException e)
                    {
                        // Wrong passphrase for this block.
                    }
                }
            }
        }

        throw new PGPException("Decryption failed.");
    }

    private static byte[] decryptIntern(InputStream inputStream)
        throws IOException
    {
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(inputStream);
        Object object = objectFactory.nextObject();
        if (object instanceof PGPCompressedData)
        {
            PGPCompressedData compressedData = (PGPCompressedData)object;
            return decryptIntern(compressedData.getInputStream());
        }
        else if (object instanceof PGPLiteralData)
        {
            PGPLiteralData literalData = (PGPLiteralData)object;
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            Streams.pipeAll(literalData.getInputStream(), outputStream);
            return outputStream.toByteArray();
        }
        return null;
    }

    public String getName()
    {
        return "RewindTest";
    }

    public static void main(String[] args)
        throws Exception
    {
        runTest(new RewindStreamWhenDecryptingMultiSKESKMessageTest());
    }
}
