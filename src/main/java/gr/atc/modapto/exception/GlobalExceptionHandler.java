package gr.atc.modapto.exception;

import gr.atc.modapto.controller.ApiResponseInfo;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import static gr.atc.modapto.exception.CustomExceptions.*;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<ApiResponseInfo<Map<String, String>>> handleValidationExceptions(@NotNull
            MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        return new ResponseEntity<>(ApiResponseInfo.error("Validation failed", errors),
                HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ResponseEntity<ApiResponseInfo<Map<String, String>>> invalidSecurityException(@NotNull
            AccessDeniedException ex) {
        return new ResponseEntity<>(ApiResponseInfo.error("Invalid authorization parameters. You don't have the rights to access the resource or check the JWT and CSRF Tokens", ex.getCause()),
                HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(KeycloakException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<ApiResponseInfo<String>> keycloakAccessError(@NotNull KeycloakException ex) {
        ApiResponseInfo<String> response = ApiResponseInfo.error(ex.getMessage(), null);
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(DataRetrievalException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<ApiResponseInfo<String>> dataRetrievalError(@NotNull DataRetrievalException ex) {
        ApiResponseInfo<String> response = ApiResponseInfo.error(ex.getMessage(), null);
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<ApiResponseInfo<String>> handleGeneralException(@NotNull Exception ex) {
        return new ResponseEntity<>(ApiResponseInfo
                .error("An unexpected error occurred", ex.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}