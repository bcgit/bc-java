package org.bouncycastle.oer;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.asn1.ASN1Encodable;

public class OEREncoder
{
    public static byte[] toByteArray(ASN1Encodable encodable, Element oerElement)
    {
        try
        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            new OEROutputStream(bos).write(encodable, oerElement);
            bos.flush();
            bos.close();
            return bos.toByteArray();
        }
        catch (Exception ex)
        {
            throw new IllegalStateException(ex.getMessage(), ex);
        }
    }

//    public static byte[] toByteArrayLogging(ASN1Encodable encodable, OERDefinition.Element oerElement)
//    {
//        try
//        {
//            ByteArrayOutputStream bos = new ByteArrayOutputStream();
//            new OEROutputStream(new FilterOutputStream(bos)
//            {
//                @Override
//                public void write(int b)
//                    throws IOException
//                {
//                    System.out.print(Hex.toHexString(new byte[]{(byte)(b & 0xFF)}));
//                    super.write(b);
//                }
//
//                @Override
//                public void write(byte[] b)
//                    throws IOException
//                {
//                    System.out.print(Hex.toHexString(b));
//                    super.write(b);
//                }
//
//                @Override
//                public void write(byte[] b, int off, int len)
//                    throws IOException
//                {
//                    Hex.toHexString(b, 0, len);
//                    super.write(b, off, len);
//                }
//            })
//            {
//                {
//                    debugOutput = new PrintWriter(System.out);
//                }
//            }.write(encodable, oerElement);
//            bos.flush();
//            bos.close();
//            return bos.toByteArray();
//        }
//        catch (Exception ex)
//        {
//            throw new IllegalStateException(ex.getMessage(), ex);
//        }
//    }

}
