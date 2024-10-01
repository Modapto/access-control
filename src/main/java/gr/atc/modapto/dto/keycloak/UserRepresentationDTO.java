package gr.atc.modapto.dto.keycloak;

import com.fasterxml.jackson.annotation.JsonProperty;
import gr.atc.modapto.dto.UserDTO;
import gr.atc.modapto.enums.PilotCode;
import gr.atc.modapto.enums.PilotRole;
import gr.atc.modapto.enums.UserRole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserRepresentationDTO {

    private static final String PILOT = "pilot";
    private static final String PILOT_ROLE = "pilot_role";
    private static final String PILOT_TYPE = "pilot_type";

    @JsonProperty
    private String id;

    @JsonProperty("email")
    private String email;

    @JsonProperty("emailVerified")
    private boolean emailVerified;

    @JsonProperty("enabled")
    private boolean enabled;

    @JsonProperty("firstName")
    private String firstName;

    @JsonProperty("lastName")
    private String lastName;

    @JsonProperty("username")
    private String username;

    @JsonProperty("credentials")
    private List<CredentialRepresentationDTO> credentials;

    @JsonProperty("attributes")
    private Map<String, List<String>> attributes;

    @JsonProperty("groups")
    private List<String> groups;

    // Used both for creating and updating a User
    public static UserRepresentationDTO fromUserDTO(UserDTO user, UserRepresentationDTO existingUser) {
        if (user == null)
            return null;

        UserRepresentationDTO keycloakUser = existingUser != null ? existingUser : new UserRepresentationDTO();

        keycloakUser.setEnabled(true);

        if (user.getFirstName() != null) {
            keycloakUser.setFirstName(user.getFirstName());
        }

        if (user.getLastName() != null) {
            keycloakUser.setLastName(user.getLastName());
        }

        if (user.getEmail() != null) {
            keycloakUser.setEmail(user.getEmail());
            keycloakUser.setEmailVerified(true);
        }

        if (user.getUsername() != null) {
            keycloakUser.setUsername(user.getUsername());
        }

        if (user.getPassword() != null) {
            keycloakUser.setCredentials(List.of(
                    CredentialRepresentationDTO.builder()
                            .temporary(false)
                            .type("password")
                            .value(user.getPassword())
                            .build()));
        }

        if (keycloakUser.getAttributes() == null) {
            keycloakUser.setAttributes(new HashMap<>());
        }

        if (user.getUserRole() != null) {
            keycloakUser.getAttributes().put(PILOT_ROLE, List.of(user.getUserRole().toString()));
        }

        if (user.getPilotRole() != null) {
            keycloakUser.getAttributes().put(PILOT_TYPE, List.of(user.getPilotRole().toString()));
        }

        if (user.getPilotCode() != null && user.getPilotCode() != PilotCode.NONE) {
            String pilotType = "/" + user.getPilotCode() + "/" + user.getPilotRole();
            keycloakUser.setGroups(List.of("/" + user.getPilotCode(), pilotType));
            keycloakUser.getAttributes().put(PILOT, List.of(user.getPilotCode().toString()));
        }

        return keycloakUser;
    }

    public static UserDTO toUserDTO(UserRepresentationDTO keycloakUser) {
        return UserDTO.builder()
                .userId(keycloakUser.getId() != null ? keycloakUser.getId() : null)
                .email(keycloakUser.getEmail() != null ? keycloakUser.getEmail() : null)
                .firstName(keycloakUser.getFirstName() != null ? keycloakUser.getFirstName() : null)
                .lastName(keycloakUser.getLastName() != null ? keycloakUser.getLastName() : null)
                .username(keycloakUser.getUsername() != null ? keycloakUser.getUsername() : null)
                .userRole(keycloakUser.getAttributes() != null && keycloakUser.getAttributes().containsKey(PILOT_ROLE) && !keycloakUser.getAttributes().get(PILOT_ROLE).isEmpty() ? UserRole.valueOf(keycloakUser.getAttributes().get(PILOT_ROLE).getFirst()) : null)
                .pilotCode(keycloakUser.getAttributes() != null && keycloakUser.getAttributes().containsKey(PILOT) && !keycloakUser.getAttributes().get(PILOT).isEmpty() ? PilotCode.valueOf(keycloakUser.getAttributes().get(PILOT).getFirst()) : null)
                .pilotRole(keycloakUser.getAttributes() != null && keycloakUser.getAttributes().containsKey(PILOT_TYPE) && !keycloakUser.getAttributes().get(PILOT_TYPE).isEmpty() ? PilotRole.valueOf(keycloakUser.getAttributes().get(PILOT_TYPE).getFirst()) : null)
                .build();
    }
}
