package com.github.gv2011.asn1.dump;

import java.io.FileInputStream;

import com.github.gv2011.asn1.ASN1InputStream;

public class Dump
{
    public static void main(
        final String args[])
        throws Exception
    {
        try(final ASN1InputStream bIn = new ASN1InputStream(new FileInputStream(args[0]))){
          Object          obj = null;

          while ((obj = bIn.readObject()) != null)
          {
              System.out.println(ASN1Dump.dumpAsString(obj));
          }
        }
    }
}
