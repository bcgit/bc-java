package org.bouncycastle.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A {@link RuntimeException} that carries several underlying exceptions rather than a single
 * cause - for example the complete set of problems found when reviewing a malformed structure,
 * where surfacing only the first would lose information.
 */
public class AggregateRuntimeException
    extends RuntimeException
{
    private final List exceptions;

    /**
     * Base constructor.
     *
     * @param message a message concerning the exception.
     * @param exceptions the underlying exceptions making up this aggregate (may be null or empty).
     */
    public AggregateRuntimeException(String message, List exceptions)
    {
        super(message);

        this.exceptions = (exceptions == null)
            ? Collections.EMPTY_LIST
            : Collections.unmodifiableList(new ArrayList(exceptions));
    }

    /**
     * Return the exceptions that make up this aggregate.
     *
     * @return an unmodifiable list of the aggregated exceptions, in the order supplied.
     */
    public List getExceptions()
    {
        return exceptions;
    }
}
