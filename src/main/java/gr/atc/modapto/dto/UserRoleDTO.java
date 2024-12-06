package gr.atc.modapto.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import gr.atc.modapto.enums.PilotCode;
import gr.atc.modapto.enums.PilotRole;
import gr.atc.modapto.validation.ValidPilotCode;
import gr.atc.modapto.validation.ValidPilotRole;
import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserRoleDTO {
    /**
     * DTO to create / retrieve a new User Role
     */
    @JsonProperty("id")
    private String id;

    @JsonProperty("name")
    private String name;

    @ValidPilotCode
    @JsonProperty("pilotCode")
    private PilotCode pilotCode;

    @ValidPilotRole
    @JsonProperty("pilotRole")
    private PilotRole pilotRole;
}
