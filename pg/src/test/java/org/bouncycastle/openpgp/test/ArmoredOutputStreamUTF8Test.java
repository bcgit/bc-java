package org.bouncycastle.openpgp.test;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

public class ArmoredOutputStreamUTF8Test
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new ArmoredOutputStreamUTF8Test());
    }

    public String getName()
    {
        return "ArmoredOutputStreamUTF8Test";
    }

    public void performTest()
        throws Exception
    {
        // Hex.decode("c384c396c39cc39f26556d6c61757473")
        String utf8WithUmlauts = "ÄÖÜß&Umlauts";

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(out);
        armorOut.setHeader("Comment", utf8WithUmlauts);
        armorOut.write(Strings.toUTF8ByteArray("Foo\nBar"));
        armorOut.close();

        byte[] armoredOutputUTF8 = out.toByteArray();

        String comment = findComment(armoredOutputUTF8);
        String[] headers = parseHeaders(armoredOutputUTF8);

        isTrue("We did not find the comment line. This MUST never happen.", comment != null);
        isEquals("Comment was not properly encoded. Expected: " + utf8WithUmlauts + ", Actual: " + comment, comment, utf8WithUmlauts);

        // round-tripped comment from ascii armor input stream
        isEquals(headers[1].substring("Comment: ".length()), utf8WithUmlauts);
    }

    private String findComment(byte[] armoredOutputUTF8)
        throws IOException
    {
        BufferedReader br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(armoredOutputUTF8), "UTF-8"));
        String comment = null;
        String line;
        while ((line = br.readLine()) != null)
        {
            if (line.startsWith("Comment: "))
            {
                comment = line.substring("Comment: ".length());
                break;
            }
        }
        br.close();
        return comment;
    }

    private String[] parseHeaders(byte[] armoredOutput)
        throws IOException
    {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(armoredOutput);
        ArmoredInputStream armorIn = new ArmoredInputStream(bytesIn);
        String[] header = armorIn.getArmorHeaders();
        armorIn.close();
        return header;
    }
}
