package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class ArmoredInputStreamCRCErrorGetsThrownTest
    extends SimpleTest
{

    public static final String ASCII_ARMOR_CRC_MISMATCH = "" +
        "-----BEGIN PGP MESSAGE-----\n" +
        "Version: FlowCrypt 5.0.4 Gmail Encryption flowcrypt.com\n" +
        "Comment: Seamlessly send, receive and search encrypted email\n" +
        "\n" +
        "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\n" +
        "Oi6sJ7pWuYTfWldZqTVmaBjlv0zuXQ8Eo8o/USvoTs+oihYIMcqReqdeqr/N\n" +
        "e+sDtYKRg/LKp/JJ5nAQzVMP67DxkgwLNxx0ijBLysaQmvRlsiYWayxZB1Xd\n" +
        "BxA2bjZRvsmww+hgSKNlcsiubJGBqfqvgmlebZuJHHSC1L6mdMYgcihKmYAj\n" +
        "p+HFLyqgyeRVMdjRHcrEdxNPG4fJmlk1bYiVQQ4XAd72w+AHS/seZ5HzbAK0\n" +
        "omuHYUD5PTEqZ1K9JObSsh3XMUkJK+z3BnrOxnTOOyG2r+4FxizH6rfz/Pgg\n" +
        "sPxqxE9ELUlgQe8plcPFge6aN9tUoSe+vMtDaEAqKw9JwofBF7jlxTqMMvQC\n" +
        "gWbn9x3W5o4VrnpjYGtPl8sh1QREu0A+0PUJAKL4A3GSMYRouGewLSMNJlOg\n" +
        "/0pPF6qB+Fi4GJ7ju5C07tfr9z9UqRj09kDXJuoJd95NdSiCz6ndugn6gs8B\n" +
        "Qf/XPxZVefeMLiB6p8pG0iZ/jcJjyYJLtTg6kA+1/ffmJPfH/76ZA9dgEJLj\n" +
        "/W2u0Lp4NY8cwqcXuGKgl72TVJ34Iawl35Y0yr47k/7Y1vEQ5Q3bT7HP5A==\n" +
        "=FdCC\n" +
        "-----END PGP MESSAGE-----";

    
    public String getName()
    {
        return "ArmoredInputStreamCRCErrorGetsThrowsTest";
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ArmoredInputStreamCRCErrorGetsThrownTest());
    }

    public void performTest()
        throws IOException
    {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(Strings.toByteArray(ASCII_ARMOR_CRC_MISMATCH));
        ArmoredInputStream armorIn = new ArmoredInputStream(bytesIn);
        ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();

        try
        {
            Streams.pipeAll(armorIn, bytesOut);
            fail("Expected IOException to be thrown due to CRC mismatch.");
        }
        catch (IOException e)
        {
            isEquals("crc check failed in armored message", e.getMessage());
        }
    }
}
