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
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import gr.atc.modapto.controller.BaseResponse;
import static gr.atc.modapto.exception.CustomExceptions.*;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<BaseResponse<Map<String, String>>> handleValidationExceptions(@NotNull
            MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        return new ResponseEntity<>(BaseResponse.error("Validation failed", errors),
                HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<BaseResponse<String>> handleHttpMessageNotReadableException(HttpMessageNotReadableException ex) {
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
                        .body(BaseResponse.error("Validation failed", errorMessage));
            }
        }

        // Generic error handling
        return ResponseEntity
                .badRequest()
                .body(BaseResponse.error("Validation failed"));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ResponseEntity<BaseResponse<String>> resourceNotFound(@NonNull NoResourceFoundException ex){
        return new ResponseEntity<>(BaseResponse.error("Resource not found", ex.getMessage()), HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(HandlerMethodValidationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<BaseResponse<String>> resourceNotFound(@NonNull HandlerMethodValidationException ex){
        return new ResponseEntity<>(BaseResponse.error("Validation Error", "Invalid input field"), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ResponseEntity<BaseResponse<Map<String, String>>> invalidSecurityException(@NotNull AccessDeniedException ex) {
        return new ResponseEntity<>(BaseResponse.error("Invalid authorization parameters. You don't have the rights to access the resource or check the JWT and CSRF Tokens", ex.getCause()),
                HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(InvalidAuthenticationCredentials.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseEntity<BaseResponse<Map<String, String>>> invalidAuthCredentials(@NotNull InvalidAuthenticationCredentials ex) {
        return new ResponseEntity<>(BaseResponse.error("Invalid authorization credentials provided.", ex.getCause()),
                HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(InvalidActivationAttributes.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ResponseEntity<BaseResponse<Map<String, String>>> invalidActivationAttributes(@NotNull InvalidActivationAttributes ex) {
        return new ResponseEntity<>(BaseResponse.error(ex.getMessage()), HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(KeycloakException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<BaseResponse<String>> keycloakAccessError(@NotNull KeycloakException ex) {
        BaseResponse<String> response = BaseResponse.error(ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(DataRetrievalException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ResponseEntity<BaseResponse<String>> dataRetrievalError(@NotNull DataRetrievalException ex) {
        BaseResponse<String> response = BaseResponse.error(ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<BaseResponse<String>> handleGeneralException(@NotNull Exception ex) {
        return new ResponseEntity<>(BaseResponse
                .error("An unexpected error occurred", ex.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}