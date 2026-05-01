package org.bouncycastle.tsp.test;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.tsp.Accuracy;
import org.bouncycastle.tsp.GenTimeAccuracy;

public class GenTimeAccuracyUnitTest
    extends TestCase
{
    public void testOneTwoThree()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ASN1Integer.ONE, ASN1Integer.TWO, ASN1Integer.THREE));
        
        checkValues(accuracy, ASN1Integer.ONE, ASN1Integer.TWO, ASN1Integer.THREE);
        
        checkToString(accuracy, "1.002003");
    }

    public void testThreeTwoOne()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ASN1Integer.THREE, ASN1Integer.TWO, ASN1Integer.ONE));
        
        checkValues(accuracy, ASN1Integer.THREE, ASN1Integer.TWO, ASN1Integer.ONE);
        
        checkToString(accuracy, "3.002001");
    }
    
    public void testTwoThreeTwo()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ASN1Integer.TWO, ASN1Integer.THREE, ASN1Integer.TWO));
        
        checkValues(accuracy, ASN1Integer.TWO, ASN1Integer.THREE, ASN1Integer.TWO);
        
        checkToString(accuracy, "2.003002");
    }
    

    public void testZeroTwoThree()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ASN1Integer.ZERO, ASN1Integer.TWO, ASN1Integer.THREE));
        
        checkValues(accuracy, ASN1Integer.ZERO, ASN1Integer.TWO, ASN1Integer.THREE);
        
        checkToString(accuracy, "0.002003");
    }

    public void testThreeTwoNull()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ASN1Integer.THREE, ASN1Integer.TWO, null));
        
        checkValues(accuracy, ASN1Integer.THREE, ASN1Integer.TWO, ASN1Integer.ZERO);
        
        checkToString(accuracy, "3.002000");
    }
    
    public void testOneNullOne()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ASN1Integer.ONE, null, ASN1Integer.ONE));
        
        checkValues(accuracy, ASN1Integer.ONE, ASN1Integer.ZERO, ASN1Integer.ONE);
        
        checkToString(accuracy, "1.000001");
    }
    
    public void testZeroNullNull()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ASN1Integer.ZERO, null, null));
        
        checkValues(accuracy, ASN1Integer.ZERO, ASN1Integer.ZERO, ASN1Integer.ZERO);
        
        checkToString(accuracy, "0.000000");
    }
    
    public void testNullNullNull()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(null, null, null));
        
        checkValues(accuracy, ASN1Integer.ZERO, ASN1Integer.ZERO, ASN1Integer.ZERO);
        
        checkToString(accuracy, "0.000000");
    }
    
    private void checkValues(
        GenTimeAccuracy accuracy,
        ASN1Integer      secs,
        ASN1Integer      millis,
        ASN1Integer      micros)
    {
        assertEquals(secs.intValueExact(), accuracy.getSeconds());
        assertEquals(millis.intValueExact(), accuracy.getMillis());
        assertEquals(micros.intValueExact(), accuracy.getMicros());
    }
    
    private void checkToString(
        GenTimeAccuracy accuracy,
        String          expected)
    {
        assertEquals(expected, accuracy.toString());
    }
}
