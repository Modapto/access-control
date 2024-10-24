package gr.atc.modapto.exception;

public class CustomExceptions {

    private CustomExceptions(){}

    public static class KeycloakException extends RuntimeException {
        public KeycloakException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class DataRetrievalException extends RuntimeException{
        public DataRetrievalException(String message) {
            super(message);
        }
    }
}
