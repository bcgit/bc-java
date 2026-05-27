package org.bouncycastle.util.utiltest;

import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.util.AggregateRuntimeException;

public class AggregateRuntimeExceptionTest
    extends TestCase
{
    public void testMessageAndExceptions()
    {
        IllegalArgumentException e1 = new IllegalArgumentException("first");
        IllegalStateException e2 = new IllegalStateException("second");

        List supplied = new ArrayList();
        supplied.add(e1);
        supplied.add(e2);

        AggregateRuntimeException ex = new AggregateRuntimeException("two problems", supplied);

        assertEquals("two problems", ex.getMessage());
        assertEquals(2, ex.getExceptions().size());
        assertSame(e1, ex.getExceptions().get(0));
        assertSame(e2, ex.getExceptions().get(1));
        assertTrue(ex instanceof RuntimeException);
    }

    public void testExceptionsAreDefensivelyCopied()
    {
        List supplied = new ArrayList();
        supplied.add(new IllegalArgumentException("first"));

        AggregateRuntimeException ex = new AggregateRuntimeException("msg", supplied);

        // mutating the supplied list must not affect the stored exceptions
        supplied.add(new IllegalArgumentException("second"));

        assertEquals(1, ex.getExceptions().size());
    }

    public void testReturnedListIsUnmodifiable()
    {
        List supplied = new ArrayList();
        supplied.add(new IllegalArgumentException("first"));

        AggregateRuntimeException ex = new AggregateRuntimeException("msg", supplied);

        try
        {
            ex.getExceptions().add(new IllegalArgumentException("nope"));
            fail("expected UnsupportedOperationException");
        }
        catch (UnsupportedOperationException expected)
        {
            // ok
        }
    }

    public void testNullExceptionsYieldsEmptyList()
    {
        AggregateRuntimeException ex = new AggregateRuntimeException("msg", null);

        assertNotNull(ex.getExceptions());
        assertTrue(ex.getExceptions().isEmpty());
    }

    public void testCanBeThrownAndCaughtAsRuntimeException()
    {
        List supplied = new ArrayList();
        supplied.add(new IllegalArgumentException("boom"));

        try
        {
            throw new AggregateRuntimeException("aggregate", supplied);
        }
        catch (RuntimeException e)
        {
            assertTrue(e instanceof AggregateRuntimeException);
            assertEquals(1, ((AggregateRuntimeException)e).getExceptions().size());
        }
    }
}
