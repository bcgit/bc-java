package org.bouncycastle.crypto.split;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

import org.bouncycastle.crypto.split.message.KMIPMessage;

public class KMIPInputStream
{
    private final InputStream stream;
    private XMLEventReader eventReader;

    public KMIPInputStream(InputStream stream)
        throws XMLStreamException
    {
        this.stream = stream;
        this.eventReader = XMLInputFactory.newInstance().createXMLEventReader(stream);
    }

    public KMIPMessage[] parse()
        throws XMLStreamException
    {
        ArrayList<KMIPMessage> messages = new ArrayList<KMIPMessage>();
        try
        {
            while (eventReader.hasNext())
            {
                XMLEvent event = eventReader.nextEvent();

                // Process the start elements
                if (event.isStartElement())
                {
                    StartElement startElement = event.asStartElement();

                    System.out.print("Start Element: " + startElement.getName().getLocalPart());

                    // Print attributes if there are any
                    if (startElement.getAttributes() != null)
                    {
                        for (Iterator it = startElement.getAttributes(); it.hasNext(); )
                        {
                            Attribute attribute = (Attribute)it.next();
                            System.out.print(" [Attribute: " + attribute.getName() + " = " + attribute.getValue() + "]");
                        }
                    }
                    System.out.println(); // Move to the next line
                }

                // Process end elements
                if (event.isEndElement())
                {
                    EndElement endElement = event.asEndElement();
                    System.out.println("End Element: " + endElement.getName().getLocalPart());
                }
            }
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }


        return (KMIPMessage[])messages.toArray();
    }
}
