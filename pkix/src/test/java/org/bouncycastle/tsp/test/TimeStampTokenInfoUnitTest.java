package org.bouncycastle.tsp.test;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;

import junit.framework.Assert;
import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.tsp.GenTimeAccuracy;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class TimeStampTokenInfoUnitTest
    extends TestCase
{
    private static final byte[] tstInfo1 = Hex.decode(
        "303e02010106022a033021300906052b0e03021a050004140000000000000000000000000000000000000000"
            + "020118180f32303035313130313038313732315a");

    private static final byte[] tstInfo2 = Hex.decode(
        "304c02010106022a033021300906052b0e03021a05000414ffffffffffffffffffffffffffffffffffffffff"
            + "020117180f32303035313130313038323934355a3009020103800101810102020164");

    private static final byte[] tstInfo3 = Hex.decode(
        "304f02010106022a033021300906052b0e03021a050004140000000000000000000000000000000000000000"
            + "020117180f32303035313130313038343733355a30090201038001018101020101ff020164");

    private static final byte[] tstInfoDudDate = Hex.decode(
        "303e02010106022a033021300906052b0e03021a050004140000000000000000000000000000000000000000"
            + "020118180f32303030563130313038313732315a");

    public void testTstInfo1()
        throws Exception
    {
        TimeStampTokenInfo tstInfo = getTimeStampTokenInfo(tstInfo1);

        //
        // verify
        //
        GenTimeAccuracy accuracy = tstInfo.getGenTimeAccuracy();

        assertNull(accuracy);

        assertEquals(new BigInteger("24"), tstInfo.getSerialNumber());

        assertEquals(1130833041000L, tstInfo.getGenTime().getTime());

        assertEquals("1.2.3", tstInfo.getPolicy().getId());

        assertEquals(false, tstInfo.isOrdered());

        assertNull(tstInfo.getNonce());

        Assert.assertEquals(TSPAlgorithms.SHA1, tstInfo.getMessageImprintAlgOID());

        assertTrue(Arrays.areEqual(new byte[20], tstInfo.getMessageImprintDigest()));

        assertTrue(Arrays.areEqual(tstInfo1, tstInfo.getEncoded()));
    }

    public void testTstInfo2()
        throws Exception
    {
        TimeStampTokenInfo tstInfo = getTimeStampTokenInfo(tstInfo2);

        //
        // verify
        //
        GenTimeAccuracy accuracy = tstInfo.getGenTimeAccuracy();

        assertEquals(3, accuracy.getSeconds());
        assertEquals(1, accuracy.getMillis());
        assertEquals(2, accuracy.getMicros());

        assertEquals(new BigInteger("23"), tstInfo.getSerialNumber());

        assertEquals(1130833785000L, tstInfo.getGenTime().getTime());

        assertEquals("1.2.3", tstInfo.getPolicy().getId());

        assertEquals(false, tstInfo.isOrdered());

        assertEquals(tstInfo.getNonce(), BigInteger.valueOf(100));

        assertTrue(Arrays.areEqual(Hex.decode("ffffffffffffffffffffffffffffffffffffffff"), tstInfo.getMessageImprintDigest()));

        assertTrue(Arrays.areEqual(tstInfo2, tstInfo.getEncoded()));
    }

    public void testTstInfo3()
        throws Exception
    {
        TimeStampTokenInfo tstInfo = getTimeStampTokenInfo(tstInfo3);

        //
        // verify
        //
        GenTimeAccuracy accuracy = tstInfo.getGenTimeAccuracy();

        assertEquals(3, accuracy.getSeconds());
        assertEquals(1, accuracy.getMillis());
        assertEquals(2, accuracy.getMicros());

        assertEquals(new BigInteger("23"), tstInfo.getSerialNumber());

        assertEquals(1130834855000L, tstInfo.getGenTime().getTime());

        assertEquals("1.2.3", tstInfo.getPolicy().getId());

        assertEquals(true, tstInfo.isOrdered());

        assertEquals(tstInfo.getNonce(), BigInteger.valueOf(100));

        assertEquals(TSPAlgorithms.SHA1, tstInfo.getMessageImprintAlgOID());

        assertTrue(Arrays.areEqual(new byte[20], tstInfo.getMessageImprintDigest()));

        assertTrue(Arrays.areEqual(tstInfo3, tstInfo.getEncoded()));
    }

    public void testTstInfoDudDate()
        throws Exception
    {
        try
        {
            getTimeStampTokenInfo(tstInfoDudDate);

            fail("dud date not detected.");
        }
        catch (TSPException e)
        {
            // expected
        }
    }

    private TimeStampTokenInfo getTimeStampTokenInfo(
        byte[] tstInfo)
        throws Exception
    {
        ASN1InputStream aIn = new ASN1InputStream(tstInfo);
        TSTInfo info = TSTInfo.getInstance(aIn.readObject());

        final Constructor constructor = TimeStampTokenInfo.class.getDeclaredConstructor(TSTInfo.class);

        constructor.setAccessible(true);

        try
        {
            return (TimeStampTokenInfo)constructor.newInstance(new Object[]{info});
        }
        catch (InvocationTargetException e)
        {
            throw (Exception)e.getTargetException();
        }
    }
}
