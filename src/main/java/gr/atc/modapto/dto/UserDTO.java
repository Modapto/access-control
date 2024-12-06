package gr.atc.modapto.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import gr.atc.modapto.enums.PilotCode;
import gr.atc.modapto.enums.PilotRole;
import gr.atc.modapto.enums.UserRole;
import gr.atc.modapto.validation.ValidPassword;
import gr.atc.modapto.validation.ValidPilotCode;
import gr.atc.modapto.validation.ValidPilotRole;
import gr.atc.modapto.validation.ValidUserRole;
import jakarta.validation.constraints.Email;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserDTO {

    @JsonProperty("userId")
    private String userId;

    @JsonProperty("username")
    private String username;

    @ValidPassword
    @JsonProperty("password")
    private String password;

    @JsonProperty("firstName")
    private String firstName;

    @JsonProperty("lastName")
    private String lastName;

    @Email
    @JsonProperty("email")
    private String email;

    @ValidUserRole
    @JsonProperty("userRole")
    private UserRole userRole;

    @ValidPilotRole
    @JsonProperty("pilotRole")
    private PilotRole pilotRole;

    @ValidPilotCode
    @JsonProperty("pilotCode")
    private PilotCode pilotCode;

    @JsonProperty("activationToken")
    private String activationToken;

    @JsonProperty("activationExpiry")
    private String activationExpiry;

}
