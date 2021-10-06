package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class LiteralDataGeneratorTest extends SimpleTest {

    public static void main(String[] args) throws Exception {
        new LiteralDataGeneratorTest().performTest();
    }
    @Override
    public String getName() {
        return LiteralDataGeneratorTest.class.getSimpleName();
    }

    @Override
    public void performTest() throws Exception {
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armor = new ArmoredOutputStream(out);
        OutputStream literalOut = literalDataGenerator.open(armor, PGPLiteralDataGenerator.BINARY, "", new Date(), new byte[1<<9]);

        String msg = "Foo\nBar";
        Streams.pipeAll(new ByteArrayInputStream(msg.getBytes(StandardCharsets.UTF_8)), literalOut);
        literalDataGenerator.close();
        armor.close();

        ArmoredInputStream armorIn = new ArmoredInputStream(new ByteArrayInputStream(out.toByteArray()));
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(armorIn);
        PGPLiteralData literalData = (PGPLiteralData) objectFactory.nextObject();

        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(literalData.getDataStream(), plainOut);
        System.out.println(Arrays.toString(plainOut.toByteArray()));
    }
}
