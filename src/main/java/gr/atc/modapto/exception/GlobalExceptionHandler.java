package gr.atc.modapto.exception;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.lang.NonNull;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import gr.atc.modapto.controller.ApiResponseInfo;
import gr.atc.modapto.exception.CustomExceptions.DataRetrievalException;
import gr.atc.modapto.exception.CustomExceptions.InvalidActivationAttributes;
import gr.atc.modapto.exception.CustomExceptions.KeycloakException;

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

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponseInfo<String>> handleHttpMessageNotReadableException(HttpMessageNotReadableException ex) {
        String errorMessage;

        // Check if instance is for InvalidFormat Validation
        if (ex.getCause() instanceof InvalidFormatException invalidFormatEx) {
            if (invalidFormatEx.getTargetType().isEnum()) {
                String fieldName = invalidFormatEx.getPath().getFirst().getFieldName();
                String invalidValue = invalidFormatEx.getValue().toString();

                // Format the error message according to the Validation Type failure
                errorMessage = String.format("Invalid value '%s' for field '%s'. Allowed values are: %s",
                        invalidValue,
                        fieldName,
                        Arrays.stream(invalidFormatEx.getTargetType().getEnumConstants())
                                .map(Object::toString)
                                .collect(Collectors.joining(", "))
                );

                return ResponseEntity
                        .badRequest()
                        .body(ApiResponseInfo.error("Validation failed", errorMessage));
            }
        }

        // Generic error handling
        return ResponseEntity
                .badRequest()
                .body(ApiResponseInfo.error("Validation failed"));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ResponseEntity<ApiResponseInfo<String>> resourceNotFound(@NonNull NoResourceFoundException ex){
        return new ResponseEntity<>(ApiResponseInfo.error("Resource not found", ex.getMessage()), HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ResponseEntity<ApiResponseInfo<Map<String, String>>> invalidSecurityException(@NotNull AccessDeniedException ex) {
        return new ResponseEntity<>(ApiResponseInfo.error("Invalid authorization parameters. You don't have the rights to access the resource or check the JWT and CSRF Tokens", ex.getCause()),
                HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(InvalidActivationAttributes.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ResponseEntity<ApiResponseInfo<Map<String, String>>> invalidActivationAttributes(@NotNull InvalidActivationAttributes ex) {
        return new ResponseEntity<>(ApiResponseInfo.error(ex.getMessage()), HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(KeycloakException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<ApiResponseInfo<String>> keycloakAccessError(@NotNull KeycloakException ex) {
        ApiResponseInfo<String> response = ApiResponseInfo.error(ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(DataRetrievalException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ResponseEntity<ApiResponseInfo<String>> dataRetrievalError(@NotNull DataRetrievalException ex) {
        ApiResponseInfo<String> response = ApiResponseInfo.error(ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<ApiResponseInfo<String>> handleGeneralException(@NotNull Exception ex) {
        return new ResponseEntity<>(ApiResponseInfo
                .error("An unexpected error occurred", ex.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}