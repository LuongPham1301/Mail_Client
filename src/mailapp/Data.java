/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mailapp;

import java.io.File;
import java.io.IOException;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 *
 * @author hoc
 */
public class Data {
    
    Document doc;
    String path = "/home/hoc/Desktop/key/";
    Vector Users = new Vector();

    public Data()  {
        taiFile();
        NodeList dsUser = doc.getElementsByTagName("User");
        for (int i = 0; i < dsUser.getLength(); i++) {
            String username = dsUser.item(i).getAttributes().item(0).getTextContent();
            Users.add(username);
        }
    }
    
    public String getPublicKey(String username) {
        NodeList list = doc.getElementsByTagName("User");
            
            for (int i = 0; i < list.getLength(); i++) {
                Element element = (Element) list.item(i);
                
                String Username = element.getAttribute("username").toString();
                if (Username.equals(username)) 
                {
                    return element.getElementsByTagName("publicKeyPath").item(0).getTextContent();
                }
            }
            return "";
    }
            
    public String getPrivateKey(String username) {
        
        NodeList list = doc.getElementsByTagName("User");
            
            for (int i = 0; i < list.getLength(); i++) {
                Element element = (Element) list.item(i);
                
                String Username = element.getAttribute("username").toString();
                
                if (Username.equals(username)) 
                {
                    return element.getElementsByTagName("privateKeyPath").item(0).getTextContent();
                }
            }
            return "";
    }
    
    
    
    
    
    public void taiFile() 
    {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            doc = db.parse("/home/hoc/Desktop/key.xml");
        } catch (ParserConfigurationException | SAXException | IOException ex) {
            Logger.getLogger(Data.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void insert(String username,String publicKeyPath,String privateKeyPath) throws TransformerException
    {
        Element root = doc.getDocumentElement();
        
        Element User = doc.createElement("User");
        User.setAttribute("username",username);
        root.appendChild(User);

        Element PrivateKeyPath = doc.createElement("privateKeyPath");
        PrivateKeyPath.appendChild(doc.createTextNode(privateKeyPath));
        User.appendChild(PrivateKeyPath);

        Element PublicKeyPath = doc.createElement("publicKeyPath");
        PublicKeyPath.appendChild(doc.createTextNode(publicKeyPath));
        User.appendChild(PublicKeyPath);
        luuFile();
    }
    
    public void luuFile() throws TransformerConfigurationException, TransformerException
    {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource dOMSource = new DOMSource(doc);
        StreamResult streamResult = new StreamResult(new File("/home/hoc/Desktop/key.xml"));
        transformer.transform(dOMSource,streamResult);
    }
}
