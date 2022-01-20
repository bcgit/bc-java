package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class PGPUtilTest
    extends SimpleTest
{
    public String getName()
    {
        return "PGPUtilTest";
    }

    public void performTest()
        throws Exception
    {
        testCurveNames();

        byte[] contentMessage = Strings.toByteArray("Hello, world!\r\nhello, World!\r\n");

        File dataFile = File.createTempFile("bcpg", ".txt");

        FileOutputStream fOut = new FileOutputStream(dataFile);

        fOut.write(contentMessage);

        fOut.close();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPUtil.writeFileToLiteralData(bOut, 't', dataFile);

        testLiteralData("no buf", bOut.toByteArray(), dataFile.getName(), 't', contentMessage);

        bOut = new ByteArrayOutputStream();

        PGPUtil.writeFileToLiteralData(bOut, 't', dataFile, new byte[1 << 16]);

        testLiteralData("buf", bOut.toByteArray(), dataFile.getName(), 't', contentMessage);

        dataFile.delete();
    }

    private void testLiteralData(String id, byte[] data, String fileName, char type, byte[] content)
        throws IOException
    {
        PGPLiteralData ld = new PGPLiteralData(new BCPGInputStream(new ByteArrayInputStream(data)));

        isEquals(fileName, ld.getFileName());
        isTrue(type == ld.getFormat());

        byte[] bytes = Streams.readAll(ld.getDataStream());
        
        isTrue(id + " contents mismatch", Arrays.areEqual(bytes, content));
    }

    private void testCurveNames()
    {
        isEquals("Curve25519", PGPUtil.getCurveName(CryptlibObjectIdentifiers.curvey25519));
        isEquals("Curve25519", PGPUtil.getCurveName(EdECObjectIdentifiers.id_X25519));
        isEquals("Ed25519", PGPUtil.getCurveName(EdECObjectIdentifiers.id_Ed25519));
        isEquals("NIST P-256", PGPUtil.getCurveName(SECObjectIdentifiers.secp256r1));
        isEquals("NIST P-384", PGPUtil.getCurveName(SECObjectIdentifiers.secp384r1));
        isEquals("NIST P-521", PGPUtil.getCurveName(SECObjectIdentifiers.secp521r1));
        isEquals("brainpoolP256r1", PGPUtil.getCurveName(TeleTrusTObjectIdentifiers.brainpoolP256r1));
        isEquals("brainpoolP512r1", PGPUtil.getCurveName(TeleTrusTObjectIdentifiers.brainpoolP512r1));
    }

    public static void main(
        String[]    args)
    {
        runTest(new PGPUtilTest());
    }
}
