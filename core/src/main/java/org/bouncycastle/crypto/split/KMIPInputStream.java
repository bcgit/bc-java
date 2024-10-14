package org.bouncycastle.crypto.split;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

import org.bouncycastle.crypto.split.message.KMIPMessage;
import org.bouncycastle.crypto.split.message.KMIPProtocolVersion;
import org.bouncycastle.crypto.split.message.KMIPRequestHeader;

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
        throws XMLStreamException, KMIPInputException
    {
        List<Element> elements = new ArrayList<Element>();
        ArrayList<KMIPMessage> messages = new ArrayList<KMIPMessage>();
        // Get a list of elements
        try
        {
            while (eventReader.hasNext())
            {
                XMLEvent event = eventReader.nextEvent();
                if (event.isStartElement())
                {
                    StartElement startElement = event.asStartElement();
                    String name = startElement.getName().getLocalPart();
                    if (name.equals("RequestMessage") || name.equals("ResponseMessage"))
                    {
                        KMIPMessage message = parseMessage();
                    }
                }
            }
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }


        return (KMIPMessage[])messages.toArray();
    }


    public KMIPMessage parseMessage()
        throws KMIPInputException
    {
        try
        {
            while (eventReader.hasNext())
            {
                XMLEvent event = eventReader.nextEvent();
                if (event.isStartElement())
                {
                    StartElement startElement = event.asStartElement();
                    String name = startElement.getName().getLocalPart();
                    if (name.equals("RequestHeader"))
                    {
                        KMIPRequestHeader header = parseRequestHeader();
                    }
                    else if (name.equals("BatchItem"))
                    {

                    }
                }
            }
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }
        return null;
    }

    public KMIPRequestHeader parseRequestHeader()
        throws KMIPInputException
    {
        KMIPProtocolVersion protocolVersion = null;
        String clientCorrelationValue = null;
        int batchCount = -1;
        try
        {
            while (eventReader.hasNext())
            {
                XMLEvent event = eventReader.nextEvent();
                if (event.isStartElement())
                {
                    StartElement startElement = event.asStartElement();
                    String name = startElement.getName().getLocalPart();
                    if (name.equals("ProtocolVersion"))
                    {
                        protocolVersion = parseProtocolVersion();
                    }
                    else if (name.equals("ClientCorrelationValue"))
                    {
                        clientCorrelationValue = parseTextString(startElement, "Error in parsing ClientCorrelationValue: ");
                    }
                    else if (name.equals("BatchCount"))
                    {
                        batchCount = parseInteger(startElement, "Error in parsing BatchCount: ");
                    }
                    else
                    {
                        throw new KMIPInputException("Add more code to support parseRequestHeader");
                    }
                }
            }
            if (protocolVersion == null || batchCount == -1)
            {
                throw new KMIPInputException("Request Header should contain Protocol Version and Batch Count");
            }
            KMIPRequestHeader header = new KMIPRequestHeader(protocolVersion, batchCount);
            header.setClientCorrelationValue(clientCorrelationValue);
            return header;
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }
        return null;
    }

    private void assertException(Attribute attribute, String name, String value, String errorMessage)
        throws KMIPInputException
    {
        if (!attribute.getName().equals(name) || !attribute.getValue().equals(value))
        {
            //parse error
            throw new KMIPInputException(errorMessage);
        }
    }

    private void assertException(boolean condition, String errorMessage)
        throws KMIPInputException
    {
        if (condition)
        {
            throw new KMIPInputException(errorMessage);
        }
    }

    private StartElement assertStartElement(XMLEvent event, String name, String errorMessage)
        throws KMIPInputException
    {
        if (!event.isStartElement())
        {
            throw new KMIPInputException(errorMessage + "Expected Start Element for " + name);
        }
        StartElement startElement = event.asStartElement();
        if (!startElement.getName().getLocalPart().equals(name))
        {
            throw new KMIPInputException(errorMessage + "Expected " + name + "but got" + startElement.getName());
        }
        return startElement;
    }

    private EndElement assertEndElement(XMLEvent event, String name, String errorMessage)
        throws KMIPInputException
    {
        if (!event.isEndElement())
        {
            throw new KMIPInputException(errorMessage + "Expected End Element for " + name);
        }
        EndElement endElement = event.asEndElement();
        if (!endElement.getName().getLocalPart().equals(name))
        {
            throw new KMIPInputException(errorMessage + "Expected " + name + "but got" + endElement.getName());
        }
        return endElement;
    }

    private int parseInteger(StartElement startElement, String errorMessage)
        throws KMIPInputException
    {
        int value;
        if (startElement.getAttributes() != null)
        {
            Iterator it = startElement.getAttributes();
            Attribute attribute = (Attribute)it.next();
            assertException(attribute, "type", "Integer", errorMessage + " type should be integer");
            attribute = (Attribute)it.next();
            value = Integer.parseInt(attribute.getValue());
            assertException(it.hasNext(), errorMessage + "There should be 2 attributes");
        }
        else
        {
            throw new KMIPInputException(errorMessage + " there should be 2 attributes");
        }
        return value;
    }

    private String parseTextString(StartElement startElement, String errorMessage)
        throws KMIPInputException
    {
        String value;
        if (startElement.getAttributes() != null)
        {
            Iterator it = startElement.getAttributes();
            Attribute attribute = (Attribute)it.next();
            assertException(attribute, "type", "TextString", errorMessage + " type should be integer");
            attribute = (Attribute)it.next();
            value = attribute.getValue();
            assertException(it.hasNext(), errorMessage + "There should be 2 attributes");
        }
        else
        {
            throw new KMIPInputException(errorMessage + " there should be 2 attributes");
        }
        return value;
    }

    public KMIPProtocolVersion parseProtocolVersion()
        throws KMIPInputException
    {
        int marjorVersion, minorVersion;
        try
        {
            XMLEvent event = eventReader.nextEvent();
            StartElement startElement = assertStartElement(event, "ProtocolVersionMajor", "Error in processing Protocol Version: ");
            marjorVersion = parseInteger(startElement, "Error in processing Protocol Version");
            event = eventReader.nextEvent();
            assertEndElement(event, "ProtocolVersionMajor", "Error in processing Protocol Version: ");
            event = eventReader.nextEvent();
            startElement = assertStartElement(event, "ProtocolVersionMinor", "Error in processing Protocol Version: ");
            minorVersion = parseInteger(startElement, "Error in processing Protocol Version");
            event = eventReader.nextEvent();
            assertEndElement(event, "ProtocolVersionMinor", "Error in processing Protocol Version: ");
            event = eventReader.nextEvent();
            assertEndElement(event, "ProtocolVersion", "Error in processing Protocol Version: ");
            return new KMIPProtocolVersion(marjorVersion, minorVersion);
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }
        return null;
    }

    private class Element
    {
        public String name;
        public boolean isStart;
        public boolean isEnd;
        public Map<String, String> attributes;

        public Element(XMLEvent event)
        {
            // Process the start elements
            if (event.isStartElement())
            {
                StartElement startElement = event.asStartElement();
                name = startElement.getName().getLocalPart();
                isStart = true;

                // Print attributes if there are any
                if (startElement.getAttributes() != null)
                {
                    for (Iterator it = startElement.getAttributes(); it.hasNext(); )
                    {
                        Attribute attribute = (Attribute)it.next();
                        if (attributes == null)
                        {
                            attributes = new HashMap<String, String>();
                        }
                        attributes.put(attribute.getName().toString(), attribute.getValue());
                    }
                }
            }

            // Process end elements
            if (event.isEndElement())
            {
                EndElement endElement = event.asEndElement();
                name = endElement.getName().getLocalPart();
                isEnd = true;
            }
        }
    }
}
