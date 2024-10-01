package gr.atc.modapto.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailAuthenticationException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService implements IEmailService {

    private final JavaMailSender javaMailSender;

  @Value("${spring.mail.username}")
  private String mailUsername;

  public EmailService(JavaMailSender javaMailSender) {
    this.javaMailSender = javaMailSender;
  }

  @Override
  public void sendMessage(String recipientAddress, String subject, String body)
      throws MailAuthenticationException {

    SimpleMailMessage message = new SimpleMailMessage();
    message.setFrom(mailUsername);
    message.setTo(recipientAddress);
    message.setSubject(subject);
    message.setText(body);
    javaMailSender.send(message);
  }
}

