package gr.atc.modapto.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = PilotCodeValidator.class)
@Target({ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidPilotCode {
    String message() default "Invalid pilot code. Only SEW, ILTAR, FFT or CRF are applicable!";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
