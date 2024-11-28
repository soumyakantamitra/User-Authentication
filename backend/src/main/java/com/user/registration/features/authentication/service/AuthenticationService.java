package com.user.registration.features.authentication.service;

import java.io.UnsupportedEncodingException;

import com.user.registration.features.authentication.dto.AuthenticationRequestBody;
import com.user.registration.features.authentication.dto.AuthenticationResponseBody;
import com.user.registration.features.authentication.model.AuthenticationUser;

import jakarta.mail.MessagingException;

public interface AuthenticationService {

    AuthenticationUser getUser(String email);
    AuthenticationResponseBody register(AuthenticationRequestBody registerRequestBody) throws UnsupportedEncodingException, MessagingException;
    AuthenticationResponseBody login(AuthenticationRequestBody loginRequestBody);
    String generateEmailVerificationToken();
    void sendEmailVerificationToken(String email);
    void validateEmailVerificationToken(String token, String email);
    void sendPasswordResetToken(String email);
    void resetPassword(String email, String newPassword, String token);
    void blacklistToken(String token);
}
