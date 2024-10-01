package gr.atc.modapto.service;

import org.springframework.mail.MailAuthenticationException;

public interface IEmailService {

    void sendMessage(String recipientAddress, String subject, String body)
      throws MailAuthenticationException;

}