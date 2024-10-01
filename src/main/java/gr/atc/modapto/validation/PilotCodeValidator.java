package gr.atc.modapto.validation;

import org.apache.commons.lang3.EnumUtils;

import gr.atc.modapto.enums.PilotCode;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PilotCodeValidator implements ConstraintValidator<ValidPilotCode, String> {

    @Override
    public boolean isValid(String pilotCode, ConstraintValidatorContext context) {
        if (pilotCode == null) {
            return true; // No Pilot Code Inserted
        }
        // Check string value against enum values
        return EnumUtils.isValidEnumIgnoreCase(PilotCode.class, pilotCode);
    }
}
