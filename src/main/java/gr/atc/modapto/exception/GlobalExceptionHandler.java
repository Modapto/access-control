package gr.atc.modapto.exception;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.lang.NonNull;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;

import gr.atc.modapto.controller.BaseResponse;
import gr.atc.modapto.exception.CustomExceptions.DataRetrievalException;
import gr.atc.modapto.exception.CustomExceptions.InvalidActivationAttributesException;
import gr.atc.modapto.exception.CustomExceptions.InvalidAuthenticationCredentialsException;
import gr.atc.modapto.exception.CustomExceptions.InvalidResetTokenAttributesException;
import gr.atc.modapto.exception.CustomExceptions.KeycloakException;
import gr.atc.modapto.exception.CustomExceptions.ResourceAlreadyExistsException;
import gr.atc.modapto.exception.CustomExceptions.UserActivateStatusException;

@RestControllerAdvice
public class GlobalExceptionHandler {

  private static final String VALIDATION_ERROR = "Validation failed";

  @ExceptionHandler(MethodArgumentNotValidException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseEntity<BaseResponse<Map<String, String>>> validationExceptionHandler(
      @NotNull MethodArgumentNotValidException ex) {
    Map<String, String> errors = new HashMap<>();
    ex.getBindingResult().getAllErrors().forEach(error -> {
      String fieldName = ((FieldError) error).getField();
      String errorMessage = error.getDefaultMessage();
      errors.put(fieldName, errorMessage);
    });
    return new ResponseEntity<>(BaseResponse.error(VALIDATION_ERROR, errors),
        HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ResponseEntity<BaseResponse<String>> handleHttpMessageNotReadableExceptionHandler(
      HttpMessageNotReadableException ex) {
    String errorMessage;

    // Check if instance is for InvalidFormat Validation
    if (ex.getCause() instanceof InvalidFormatException invalidFormatEx
        && invalidFormatEx.getTargetType().isEnum()) {
      String fieldName = invalidFormatEx.getPath().getFirst().getFieldName();
      String invalidValue = invalidFormatEx.getValue().toString();

      // Format the error message according to the Validation Type failure
      errorMessage = String.format("Invalid value '%s' for field '%s'. Allowed values are: %s",
          invalidValue, fieldName, Arrays.stream(invalidFormatEx.getTargetType().getEnumConstants())
              .map(Object::toString).collect(Collectors.joining(", ")));

      return ResponseEntity.badRequest().body(BaseResponse.error(VALIDATION_ERROR, errorMessage));
    }

    // Generic error handling
    return ResponseEntity.badRequest().body(BaseResponse.error(VALIDATION_ERROR));
  }

  @ExceptionHandler(NoResourceFoundException.class)
  @ResponseStatus(HttpStatus.NOT_FOUND)
  public ResponseEntity<BaseResponse<String>> resourceNotFoundHandler(
      @NonNull NoResourceFoundException ex) {
    return new ResponseEntity<>(BaseResponse.error("Resource not found", ex.getMessage()),
        HttpStatus.NOT_FOUND);
  }

  @ExceptionHandler(MissingServletRequestParameterException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseEntity<BaseResponse<String>> inputNotProvidedExceptionHandler(
      @NonNull MissingServletRequestParameterException ex) {
    return new ResponseEntity<>(
        BaseResponse.error("Invalid / No input was given for requested resource", ex.getMessage()),
        HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(HandlerMethodValidationException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseEntity<BaseResponse<String>> validationExceptionHandler(
      @NonNull HandlerMethodValidationException ex) {
    return new ResponseEntity<>(BaseResponse.error("Validation Error", "Invalid input field"),
        HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(AccessDeniedException.class)
  @ResponseStatus(HttpStatus.FORBIDDEN)
  public ResponseEntity<BaseResponse<Map<String, String>>> invalidSecurityExceptionHandler(
      @NotNull AccessDeniedException ex) {
    return new ResponseEntity<>(BaseResponse.error(
        "Invalid authorization parameters. You don't have the rights to access the resource or check the JWT and CSRF Tokens",
        ex.getCause()), HttpStatus.FORBIDDEN);
  }

  @ExceptionHandler(InvalidAuthenticationCredentialsException.class)
  @ResponseStatus(HttpStatus.UNAUTHORIZED)
  public ResponseEntity<BaseResponse<Map<String, String>>> invalidAuthCredentialsHandler(
      @NotNull InvalidAuthenticationCredentialsException ex) {
    return new ResponseEntity<>(
        BaseResponse.error("Invalid authorization credentials provided.", "Authentication failed"),
        HttpStatus.UNAUTHORIZED);
  }

  @ExceptionHandler(InvalidActivationAttributesException.class)
  @ResponseStatus(HttpStatus.FORBIDDEN)
  public ResponseEntity<BaseResponse<Map<String, String>>> invalidActivationAttributesExceptionHandler(
      @NotNull InvalidActivationAttributesException ex) {
    return new ResponseEntity<>(BaseResponse.error(ex.getMessage()), HttpStatus.FORBIDDEN);
  }

  @ExceptionHandler(InvalidResetTokenAttributesException.class)
  @ResponseStatus(HttpStatus.FORBIDDEN)
  public ResponseEntity<BaseResponse<Map<String, String>>> invalidResetTokenAttributesExceptionHandler(
          @NotNull InvalidResetTokenAttributesException ex) {
    return new ResponseEntity<>(BaseResponse.error(ex.getMessage()), HttpStatus.FORBIDDEN);
  }

  @ExceptionHandler(KeycloakException.class)
  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  public ResponseEntity<BaseResponse<String>> keycloakAccessErrorHandler(@NotNull KeycloakException ex) {
    BaseResponse<String> response = BaseResponse.error(ex.getMessage());
    return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
  }

  @ExceptionHandler(DataRetrievalException.class)
  @ResponseStatus(HttpStatus.NOT_FOUND)
  public ResponseEntity<BaseResponse<String>> dataRetrievalErrorHandler(
      @NotNull DataRetrievalException ex) {
    BaseResponse<String> response = BaseResponse.error("Unable to retrieve requested data",
        ex.getMessage());
    return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
  }

  @ExceptionHandler(Exception.class)
  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  public ResponseEntity<BaseResponse<String>> handleGeneralExceptionHandler(@NotNull Exception ex) {
    return new ResponseEntity<>(BaseResponse.error("An unexpected error occurred", ex.getMessage()),
        HttpStatus.INTERNAL_SERVER_ERROR);
  }

  @ExceptionHandler(ResourceAlreadyExistsException.class)
  @ResponseStatus(HttpStatus.CONFLICT)
  public ResponseEntity<BaseResponse<String>> handleResourceAlreadyExistsExceptionHandler(@NotNull ResourceAlreadyExistsException ex) {
    return new ResponseEntity<>(BaseResponse.error("Resource already exists", ex.getMessage()),
        HttpStatus.CONFLICT);
  }

  @ExceptionHandler(UserActivateStatusException.class)
  @ResponseStatus(HttpStatus.CONFLICT)
  public ResponseEntity<BaseResponse<String>> handleUserAlreadyActivatedExceptionHandler(@NotNull UserActivateStatusException ex) {
    return new ResponseEntity<>(BaseResponse.error("Activation failed", ex.getMessage()),
        HttpStatus.CONFLICT);
  }
}
