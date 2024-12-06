package gr.atc.modapto.service;

import jakarta.mail.MessagingException;
import org.springframework.mail.MailAuthenticationException;

import java.util.concurrent.CompletableFuture;

public interface IEmailService {

    void sendMessage(String recipientAddress, String text, String subject, String fromUsername) throws MailAuthenticationException, MessagingException;

    CompletableFuture<Void> sendActivationLink(String username, String email, String activationToken);
}