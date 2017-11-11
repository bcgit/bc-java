package com.github.gv2011.asn1;

import static com.github.gv2011.util.bytes.ByteUtils.parseHex;

import org.junit.Test;

import com.github.gv2011.asn1.util.test.SimpleTest;
import com.github.gv2011.util.bytes.Bytes;

public class InputStreamTest
    extends SimpleTest
{
    private static final Bytes outOfBoundsLength = parseHex("30 ff ff ff ff ff");
    private static final Bytes negativeLength = parseHex("30 84 ff ff ff ff");
    private static final Bytes outsideLimitLength = parseHex("30 83 0f ff ff");


    @Override
    public String getName()
    {
        return "InputStream";
    }

    @Test
    @Override
    public void performTest()
        throws Exception
    {
        try(final ASN1InputStream aIn = new ASN1InputStream(outOfBoundsLength)){
          try
          {
              aIn.readObject();
              fail("out of bounds length not detected.");
          }
          catch (final ASN1ParsingException e)
          {
              if (!e.getMessage().startsWith("DER length more than 4 bytes"))
              {
                  fail("wrong exception: " + e.getMessage());
              }
          }
        }
        
        try(final ASN1InputStream aIn = new ASN1InputStream(negativeLength)){
          try
          {
              aIn.readObject();
              fail("negative length not detected.");
          }
          catch (final ASN1ParsingException e)
          {
              if (!e.getMessage().equals("corrupted stream - negative length found"))
              {
                  fail("wrong exception: " + e.getMessage());
              }
          }
        }

        try(final ASN1InputStream aIn = new ASN1InputStream(outsideLimitLength)){
          try
          {
              aIn.readObject();
              fail("outside limit length not detected.");
          }
          catch (final ASN1ParsingException e)
          {
              if (!e.getMessage().equals("corrupted stream - out of bounds length found"))
              {
                  fail("wrong exception: " + e.getMessage());
              }
          }
        }
    }
}
