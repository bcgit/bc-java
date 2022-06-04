package org.bouncycastle.asn1.util;

import java.io.FileInputStream;

import org.bouncycastle.asn1.ASN1InputStream;

/**
 * Command line ASN.1 Dump utility.
 * <p>
 *     Usage: org.bouncycastle.asn1.util.Dump ber_encoded_file
 * </p>
 */
public class Dump
{
    public static void main(
        String args[])
        throws Exception
    {
        if (args.length == 0)
        {
            // -DM System.out.println
            System.out.println("usage: Dump [-v] filename");
            System.exit(1);
        }

        FileInputStream fIn = new FileInputStream(args[0]);
        boolean verbose = (args.length > 1) ? false : args[1].equals("-v");

        try
        {
            ASN1InputStream bIn = new ASN1InputStream(fIn);
            Object obj = null;

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
