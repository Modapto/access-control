package gr.atc.modapto.service;

import java.util.concurrent.CompletableFuture;

import org.springframework.mail.MailAuthenticationException;

import jakarta.mail.MessagingException;

public interface IEmailService {

    void sendMessage(String recipientAddress, String text, String subject, String fromUsername) throws MailAuthenticationException, MessagingException;

    CompletableFuture<Void> sendActivationLink(String username, String email, String activationToken);

    CompletableFuture<Void> sendResetPasswordLink(String username, String email, String resetToken);
}