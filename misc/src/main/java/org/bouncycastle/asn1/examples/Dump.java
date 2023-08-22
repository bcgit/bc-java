package org.bouncycastle.asn1.examples;

import java.io.FileInputStream;

import org.bouncycastle.asn1.ASN1InputStream;

/**
 * Command line ASN.1 Dump utility.
 * <p>
 *     Usage: org.bouncycastle.asn1.examples.Dump [-v] ber_encoded_file
 * </p>
 */
public class Dump
{
    public static void main(String args[]) throws Exception
    {
        if (args.length < 1)
        {
            // -DM System.out.println
            System.out.println("usage: Dump [-v] filename");
            // -DM System.exit
            System.exit(1);
        }

        boolean verbose = false;

        int argsPos = 0;
        if (args.length > 1)
        {
            verbose = "-v".equals(args[argsPos++]);
        }

        FileInputStream fIn = new FileInputStream(args[argsPos++]);

        try
        {
            ASN1InputStream bIn = new ASN1InputStream(fIn);

            Object obj;
            while ((obj = bIn.readObject()) != null)
            {
                // -DM System.out.println
                System.out.println(ASN1Dump.dumpAsString(obj, verbose));
            }
        }
        finally
        {
            fIn.close();
        }
    }
}
