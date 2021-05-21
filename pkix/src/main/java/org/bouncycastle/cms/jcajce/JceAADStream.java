package org.bouncycastle.cms.jcajce;

import java.io.IOException;
import java.io.OutputStream;

import javax.crypto.Cipher;

class JceAADStream
    extends OutputStream
{
     private static final byte[] SINGLE_BYTE = new byte[1];
     private Cipher cipher;

     JceAADStream(Cipher cipher)
     {
         this.cipher = cipher;
     }

     public void write(byte[] buf, int off, int len)
         throws IOException
     {
         cipher.updateAAD(buf, off, len);
     }

     public void write(int b)
         throws IOException
     {
         SINGLE_BYTE[0] = (byte)b;
         cipher.updateAAD(SINGLE_BYTE, 0, 1);
     }
 }
