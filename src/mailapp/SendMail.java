package mailapp;

import Crypto.Crypto;
import com.sun.mail.smtp.SMTPSendFailedException;
import java.io.File;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.activation.FileDataSource;
import javax.mail.Session;
import javax.mail.Message;
import javax.mail.Transport;
import javax.mail.Authenticator;
import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.internet.InternetAddress;
import javax.mail.PasswordAuthentication;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.swing.JOptionPane;
import javax.xml.transform.TransformerException;

public class SendMail 
{

    public void send(String to, String sub,String msg,String file,String user,String pass) 
    {
        Properties props = System.getProperties();

        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");	
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.socketFactory.class", javax.net.ssl.SSLSocketFactory.class.getName());
        Session session = Session.getDefaultInstance(props,new Authenticator() 
        {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() 
            {
                return new PasswordAuthentication(user, pass);
            }
        });

        try 
        {
            Message message = new MimeMessage(session);
            
            message.setFrom(new InternetAddress(user));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
            message.setSubject(sub);
            
                BodyPart messageBodyPart = new MimeBodyPart();

                // Now set the actual message
                    messageBodyPart.setText(msg);

                // Create a multipar message
                Multipart multipart = new MimeMultipart();

                // Set text message part
                multipart.addBodyPart(messageBodyPart);
                
                if(file!=null)
                {
                // Part two is attachment
                messageBodyPart = new MimeBodyPart();
                DataSource source = new FileDataSource(file);
                messageBodyPart.setDataHandler(new DataHandler(source));
                
                messageBodyPart.setFileName(new File(file).getName());
                multipart.addBodyPart(messageBodyPart);
                }
                // Send the complete message parts
                message.setContent(multipart);
            
            

            Transport.send(message);
            
            JOptionPane.showMessageDialog(null,"Email sended!");
            
        } catch(SMTPSendFailedException ex)
        {
            JOptionPane.showMessageDialog(null,"This message was blocked because its content presents a potential");
        }
        
        catch (MessagingException e) 
        {
            JOptionPane.showMessageDialog(null,"Something happened!");
            
            throw new RuntimeException(e);
        }
        
    }
    
    public void sendPGP(String to, String sub,String msg,String file,String username,String pass,String passphrase) 
    {
        Properties props = System.getProperties();
        Crypto ce = new Crypto();
        PGPEmail email = new PGPEmail();
        Data data = new Data();
        String[] result = new String[2];
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");	
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.socketFactory.class", javax.net.ssl.SSLSocketFactory.class.getName());
        Session session = Session.getDefaultInstance(props,new Authenticator() 
        {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() 
            {
                return new PasswordAuthentication(username, pass);
            }
        });

        try 
        {
            Message message = new MimeMessage(session);
            
            message.setFrom(new InternetAddress(username));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
            message.setSubject(sub);
            
             if (!data.Users.contains(username))
                    try {
                        ce.createkeyPair(username);
            } catch (TransformerException ex) {
                Logger.getLogger(SendMail.class.getName()).log(Level.SEVERE, null, ex);
            }
            
                result = email.encryptContent(msg, username,passphrase,to);
       
                
                BodyPart messageBodyPart = new MimeBodyPart();

                // Now set the actual message
                    messageBodyPart.setText(result[1]);

                // Create a multipar message
                Multipart multipart = new MimeMultipart();

                // Set text message part
                multipart.addBodyPart(messageBodyPart);

                // Part two is attachment
                if (file != null) {
                ce.encryptFile(result[0], file);
                messageBodyPart = new MimeBodyPart();
                DataSource source = new FileDataSource("/home/hoc/Desktop/encrypted");
                messageBodyPart.setDataHandler(new DataHandler(source));
                messageBodyPart.setFileName(new File(file).getName());
                multipart.addBodyPart(messageBodyPart);
            }
                // Send the complete message parts
                message.setContent(multipart);

            

            Transport.send(message);
            
            JOptionPane.showMessageDialog(null,"Email sended!");
            
         }catch(SMTPSendFailedException ex)
        {
            JOptionPane.showMessageDialog(null,"This message was blocked because its content presents a potential");
        }
            catch (MessagingException e) 
        {
            JOptionPane.showMessageDialog(null,"Something happened!");
            
            throw new RuntimeException(e);
        } catch (TransformerException ex) {
            Logger.getLogger(SendMail.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
}