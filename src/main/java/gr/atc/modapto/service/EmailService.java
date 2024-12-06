package gr.atc.modapto.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;

@Service
@Slf4j
public class EmailService implements IEmailService {

  private final JavaMailSender javaMailSender;

  @Value("${spring.mail.username}")
  private String mailUsername;

  @Value("${app.frontend.url}")
  private String frontendUrl;

  private static final String SUBJECT = "Welcome to MODAPTO System! Activate your account";

  public EmailService(JavaMailSender javaMailSender) {
    this.javaMailSender = javaMailSender;
  }

  /**
   *  Method to send an email based on the text, subject, username and subject provided as parameters
   *
   * @param recipientAddress : To email address
   * @param text : Text to include
   * @param subject : Subject of the email
   * @param fromUsername : From email address
   */
  @Override
  public void sendMessage(String recipientAddress, String text, String subject, String fromUsername) {
    try {
      MimeMessage message = javaMailSender.createMimeMessage();
      MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
      helper.setFrom(mailUsername);
      helper.setTo(recipientAddress);
      helper.setSubject(SUBJECT);
      helper.setText(text, true);
      log.info("Will send the following message: {}", message);
      javaMailSender.send(message);
    } catch (MessagingException e) {
      log.error("Unable to send message to email: {} - Error: {}", recipientAddress, e.getMessage());
    }
  }

  /**
   * Creates a unique activation link with random generated token and a default expiration time and set it as attribute to the user
   *
   * @return CompletableFuture<Void>
   */
  @Override
  @Async("asyncPoolTaskExecutor")
  public CompletableFuture<Void> sendActivationLink(String username, String email, String activationToken) {
    return CompletableFuture.runAsync(() -> {
        // Create the activation link
        String activationLink = String.format("%s/activate?token=%s", frontendUrl, activationToken);

        // Create the email template
        String htmlContent = String.format("""
                        <!DOCTYPE html>
                        <html>
                        <head>
                          <meta charset="UTF-8">
                          <meta name="viewport" content="width=device-width, initial-scale=1.0">
                          <title>Account Activation</title>
                        </head>
                        <body style="font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; color: #333; line-height: 1.5;">
                          <div style="max-width: 600px; margin: 20px auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);">
                            <p style="font-size: 16px;">Hello %s,</p>
                        
                            <p style="font-size: 16px;">An account has been created for you in MODAPTO System. Click the button below to activate your account and set up your password.</p>
                        
                             <div style="text-align: center; margin: 40px 0;">
                                                                <a href="%s" style="
                                                                  display: inline-block;
                                                                  background-color: rgb(44, 54, 135);
                                                                  color: #ffffff;
                                                                  text-decoration: none;
                                                                  padding: 14px 22px;
                                                                  border-radius: 16px;
                                                                  font-size: 16px;
                                                                  font-weight: bold;
                                                                ">Activate Account</a>
                                <p style="text-align: center; font-size: 14px; color: #666; font-style: italic;"><strong>Note:</strong> This activation link will expire in 24 hours for security reasons.</p>
                             </div>
                        
                            <p style="font-size: 16px;">If you didn't expect this invitation or believe it was sent by error, please ignore this email or contact our support team.</p>
                        
                            <p style="font-size: 16px;">Best regards,<br>The MODAPTO Team</p>
                          </div>
                        </body>
                        </html>
                        """,
                      username,
                      activationLink
        );

        // Call function to send email
        sendMessage(email, htmlContent, SUBJECT, mailUsername);
    });
  }
}

