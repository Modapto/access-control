package gr.atc.modapto.validation;

import org.apache.commons.lang3.EnumUtils;

import gr.atc.modapto.enums.UserRole;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class UserRoleValidator implements ConstraintValidator<ValidUserRole, String> {

    @Override
    public boolean isValid(String userRole, ConstraintValidatorContext context) {
        if (userRole == null) {
            return true; // No Pilot Code Inserted
        }
        // Check string value against enum values
        return EnumUtils.isValidEnumIgnoreCase(UserRole.class, userRole);
    }
}