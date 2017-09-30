package com.github.gv2011.asn1.util.io.pem;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.github.gv2011.util.bytes.Bytes;

/**
 * A generic PEM object - type, header properties, and byte content.
 */
public class PemObject
    implements PemObjectGenerator
{
    private static final List<?> EMPTY_LIST = Collections.unmodifiableList(new ArrayList<>());

    private final String type;
    private final List<?>   headers;
    private final Bytes content;

    /**
     * Generic constructor for object without headers.
     *
     * @param type pem object type.
     * @param content the binary content of the object.
     */
    public PemObject(final String type, final Bytes content)
    {
        this(type, EMPTY_LIST, content);
    }

    /**
     * Generic constructor for object with headers.
     *
     * @param type pem object type.
     * @param headers a list of PemHeader objects.
     * @param content the binary content of the object.
     */
    public PemObject(final String type, final List<?> headers, final Bytes content)
    {
        this.type = type;
        this.headers = Collections.unmodifiableList(headers);
        this.content = content;
    }

    public String getType()
    {
        return type;
    }

    public List<?> getHeaders()
    {
        return headers;
    }

    public Bytes getContent()
    {
        return content;
    }

    @Override
    public PemObject generate()
        throws PemGenerationException
    {
        return this;
    }
}
