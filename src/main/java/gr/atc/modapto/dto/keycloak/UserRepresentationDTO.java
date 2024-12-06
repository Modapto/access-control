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

    private static final String PILOT_CODE = "pilot_code";
    private static final String PILOT_ROLE = "pilot_role";
    private static final String USER_ROLE = "user_role";
    private static final String ACTIVATION_TOKEN = "activation_token";
    private static final String ACTIVATION_EXPIRY = "activation_expiry";


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
            return existingUser;

        UserRepresentationDTO keycloakUser;
        // User will be by default disabled until he activates its account and create a new password
        if (existingUser == null) {
            keycloakUser = new UserRepresentationDTO();
            keycloakUser.setEnabled(false);
        } else {
            keycloakUser = existingUser;
            keycloakUser.setEnabled(true);
        }

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

        // Update password only if provided and we want to update the user
        if (user.getPassword() != null && existingUser != null) {
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
            keycloakUser.getAttributes().put(USER_ROLE, List.of(user.getUserRole().toString()));
        }

        if (user.getPilotRole() != null) {
            keycloakUser.getAttributes().put(PILOT_ROLE, List.of(user.getPilotRole().toString()));
        }

        if (user.getPilotCode() != null && user.getPilotCode() != PilotCode.ALL) {
            String pilotType = "/" + user.getPilotCode() + "/" + user.getPilotRole();
            keycloakUser.setGroups(List.of("/" + user.getPilotCode(), pilotType));
            keycloakUser.getAttributes().put(PILOT_CODE, List.of(user.getPilotCode().toString()));
        }

        // Set activation token and expiration time as attributes - Two cases can be observed: 1) Create a new user 2) Activate user
        if (existingUser == null && user.getActivationExpiry() != null && user.getActivationToken() != null){ // Creation of a new user
            keycloakUser.getAttributes().put(ACTIVATION_TOKEN, List.of(user.getActivationToken()));
            keycloakUser.getAttributes().put(ACTIVATION_EXPIRY, List.of(user.getActivationExpiry()));
        } else if (keycloakUser.getAttributes().containsKey(ACTIVATION_TOKEN) && keycloakUser.getAttributes().containsKey(ACTIVATION_EXPIRY)) { // This will apply only after the user has been activated
            keycloakUser.getAttributes().remove(ACTIVATION_TOKEN);
            keycloakUser.getAttributes().remove(ACTIVATION_EXPIRY);
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
                .userRole(keycloakUser.getAttributes() != null && keycloakUser.getAttributes().containsKey(USER_ROLE) && !keycloakUser.getAttributes().get(USER_ROLE).isEmpty() ? UserRole.valueOf(keycloakUser.getAttributes().get(USER_ROLE).getFirst()) : null)
                .pilotCode(keycloakUser.getAttributes() != null && keycloakUser.getAttributes().containsKey(PILOT_CODE) && !keycloakUser.getAttributes().get(PILOT_CODE).isEmpty() ? PilotCode.valueOf(keycloakUser.getAttributes().get(PILOT_CODE).getFirst()) : null)
                .pilotRole(keycloakUser.getAttributes() != null && keycloakUser.getAttributes().containsKey(PILOT_ROLE) && !keycloakUser.getAttributes().get(PILOT_ROLE).isEmpty() ? PilotRole.valueOf(keycloakUser.getAttributes().get(PILOT_ROLE).getFirst()) : null)
                .activationToken(keycloakUser.getAttributes() != null && keycloakUser.getAttributes().containsKey(ACTIVATION_TOKEN) && !keycloakUser.getAttributes().get(ACTIVATION_TOKEN).isEmpty() ? keycloakUser.getAttributes().get(ACTIVATION_TOKEN).getFirst() : null)
                .activationExpiry(keycloakUser.getAttributes() != null && keycloakUser.getAttributes().containsKey(ACTIVATION_EXPIRY) && !keycloakUser.getAttributes().get(ACTIVATION_EXPIRY).isEmpty() ? keycloakUser.getAttributes().get(ACTIVATION_EXPIRY).getFirst() : null)
                .build();
    }
}
