package org.bouncycastle.util.encoders.test;

import java.util.Arrays;
import java.util.Random;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class EncoderTest
    extends SimpleTest
{
    public static final boolean DEBUG = true;


    public static void main(
        String[]    args)
    {
        runTest(new EncoderTest());
    }

    public String getName()
    {
        return "Encoder";
    }
    
    /*
     *
     *  TESTS
     *
     */

    public void performTest()
    {
        testHex();
        testBase64();
        testBase64WithNL();
    }
    
    
    public void testBase64()
    {
        try
        {
            Random _r = new Random();
            
            byte[] _orig1024 = new byte[1024];
            _r.nextBytes(_orig1024);
            
            byte[] _orig2048 = new byte[2048];
            _r.nextBytes(_orig2048);
            
            byte[] _orig4096 = new byte[4096];
            _r.nextBytes(_orig4096);
            
            byte[] _orig8192 = new byte[8192];
            _r.nextBytes(_orig8192);
            
            byte[] _enc1024 = Base64.encode(_orig1024);
            byte[] _enc2048 = Base64.encode(_orig2048);
            byte[] _enc4096 = Base64.encode(_orig4096);
            byte[] _enc8192 = Base64.encode(_orig8192);
            
            byte[] _dec1024 = Base64.decode(_enc1024);
            byte[] _dec2048 = Base64.decode(_enc2048);
            byte[] _dec4096 = Base64.decode(_enc4096);
            byte[] _dec8192 = Base64.decode(_enc8192);
            
            if(!Arrays.equals(_orig1024, _dec1024))
            {
                fail("Failed Base64 test");
            }
            
            if(!Arrays.equals(_orig2048, _dec2048))
            {
                fail("Failed Base64 test");
            }
            
            if(!Arrays.equals(_orig4096, _dec4096))
            {
                fail("Failed Base64 test");
            }
            
            if(!Arrays.equals(_orig8192, _dec8192))
            {
                fail("Failed Base64 test");
            }
            
            
            
            byte[] _orig1025 = new byte[1025];
            _r.nextBytes(_orig1025);
            
            byte[] _orig2049 = new byte[2049];
            _r.nextBytes(_orig2049);
            
            byte[] _orig4097 = new byte[4097];
            _r.nextBytes(_orig4097);
            
            byte[] _orig8193 = new byte[8193];
            _r.nextBytes(_orig8193);
            
            byte[] _enc1025 = Base64.encode(_orig1025);
            byte[] _enc2049 = Base64.encode(_orig2049);
            byte[] _enc4097 = Base64.encode(_orig4097);
            byte[] _enc8193 = Base64.encode(_orig8193);
            
            byte[] _dec1025 = Base64.decode(_enc1025);
            byte[] _dec2049 = Base64.decode(_enc2049);
            byte[] _dec4097 = Base64.decode(_enc4097);
            byte[] _dec8193 = Base64.decode(_enc8193);
            
            if(!Arrays.equals(_orig1025, _dec1025))
            {
                fail("Failed Base64 test");
            }
            
            if(!Arrays.equals(_orig2049, _dec2049))
            {
                fail("Failed Base64 test");
            }
            
            if(!Arrays.equals(_orig4097, _dec4097))
            {
                fail("Failed Base64 test");
            }
            
            if(!Arrays.equals(_orig8193, _dec8193))
            {
                fail("Failed Base64 test");
            }
        }
        catch(Exception ex)
        {
            fail("Failed Base64 test");
        }
    }

    public void testBase64WithNL()
    {
        byte[] dec = Base64.decode("SVNC" + "\n" + "QUQ=\n");

        if (dec.length != 5)
        {
            fail("got length " + dec.length + " when expecting 10");
        }
        
        if (!areEqual(dec, Base64.decode("SVNCQUQ=")))
        {
            fail("decodings are not equal");
        }
    }
    
    public void testHex()
    {
        try
        {
            Random _r = new Random();
            
            byte[] _orig1024 = new byte[1024];
            _r.nextBytes(_orig1024);
            
            byte[] _orig2048 = new byte[2048];
            _r.nextBytes(_orig2048);
            
            byte[] _orig4096 = new byte[4096];
            _r.nextBytes(_orig4096);
            
            byte[] _orig8192 = new byte[8192];
            _r.nextBytes(_orig8192);
            
            byte[] _enc1024 = Hex.encode(_orig1024);
            byte[] _enc2048 = Hex.encode(_orig2048);
            byte[] _enc4096 = Hex.encode(_orig4096);
            byte[] _enc8192 = Hex.encode(_orig8192);
            
            byte[] _dec1024 = Hex.decode(_enc1024);
            byte[] _dec2048 = Hex.decode(_enc2048);
            byte[] _dec4096 = Hex.decode(_enc4096);
            byte[] _dec8192 = Hex.decode(_enc8192);
            
            if(!Arrays.equals(_orig1024, _dec1024))
            {
                fail("Failed Hex test");
            }
            
            if(!Arrays.equals(_orig2048, _dec2048))
            {
                fail("Failed Hex test");
            }
            
            if(!Arrays.equals(_orig4096, _dec4096))
            {
                fail("Failed Hex test");
            }
            
            if(!Arrays.equals(_orig8192, _dec8192))
            {
                fail("Failed Hex test");
            }
            
            
            byte[] _orig1025 = new byte[1025];
            _r.nextBytes(_orig1025);
            
            byte[] _orig2049 = new byte[2049];
            _r.nextBytes(_orig2049);
            
            byte[] _orig4097 = new byte[4097];
            _r.nextBytes(_orig4097);
            
            byte[] _orig8193 = new byte[8193];
            _r.nextBytes(_orig8193);
            
            byte[] _enc1025 = Hex.encode(_orig1025);
            byte[] _enc2049 = Hex.encode(_orig2049);
            byte[] _enc4097 = Hex.encode(_orig4097);
            byte[] _enc8193 = Hex.encode(_orig8193);
            
            byte[] _dec1025 = Hex.decode(_enc1025);
            byte[] _dec2049 = Hex.decode(_enc2049);
            byte[] _dec4097 = Hex.decode(_enc4097);
            byte[] _dec8193 = Hex.decode(_enc8193);
            
            if(!Arrays.equals(_orig1025, _dec1025))
            {
                fail("Failed Hex test");
            }
            
            if(!Arrays.equals(_orig2049, _dec2049))
            {
                fail("Failed Hex test");
            }
            
            if(!Arrays.equals(_orig4097, _dec4097))
            {
                fail("Failed Hex test");
            }
            
            if(!Arrays.equals(_orig8193, _dec8193))
            {
                fail("Failed Hex test");
            }
        }
        catch(Exception ex)
        {
            fail("Failed Hex test");
        }
    }
}
