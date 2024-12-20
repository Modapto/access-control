package gr.atc.modapto.dto.keycloak;

import gr.atc.modapto.dto.UserRoleDTO;
import gr.atc.modapto.enums.PilotCode;
import gr.atc.modapto.enums.PilotRole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RoleRepresentationDTO {

    private static final String PILOT_ROLE = "pilot_role";
    private static final String PILOT_CODE = "pilot_code";

    private String id;

    private String name;

    private String description;

    private boolean composite;

    private boolean clientRole;

    private String containerId; // This is the Realm ID

    private Map<String, List<String>> attributes;

    /**
     * Convert UserRoleDTO to RoleRepresentationDTO - Functionality varies according to the operation
     *
     * @param userRole: User Role DTO
     * @param existingRole : RoleRepresentationDTO for the update operation
     * @return RoleRepresentationDTO
     */
    public static RoleRepresentationDTO toRoleRepresentation(UserRoleDTO userRole, RoleRepresentationDTO existingRole) {
        RoleRepresentationDTO roleRepr = existingRole == null ? new RoleRepresentationDTO() : existingRole;

        if (userRole.getName() != null)
            roleRepr.setName(userRole.getName().isEmpty() ? roleRepr.getName() : userRole.getName().toUpperCase());

        Map<String, List<String>> attributes;
        // Used when role is initialized
        if (existingRole == null) {
            roleRepr.setComposite(false);
            roleRepr.setClientRole(true);
            attributes = new HashMap<>();
        } else {
            attributes = existingRole.getAttributes() != null ? existingRole.getAttributes() : new HashMap<>(); // Ensure that attributes is not empty or create a new HashMap
        }

        // Add pilot role attribute if included in UserRoleDTO
        Optional.ofNullable(userRole.getPilotRole())
                .map(Object::toString)
                .map(String::toUpperCase)
                .ifPresent(pilotRole -> attributes.put(PILOT_ROLE, List.of(pilotRole)));

        // Add pilot code attribute if included in UserRoleDTO
        Optional.ofNullable(userRole.getPilotCode())
                .map(Object::toString)
                .map(String::toUpperCase)
                .ifPresent(pilotCode -> attributes.put(PILOT_CODE, List.of(pilotCode)));

        // Update the attributes
        roleRepr.setAttributes(attributes);

        // Update the description
        roleRepr.setDescription("Role for pilot '" + roleRepr.getAttributes().get(PILOT_CODE).getFirst() + "' and pilot role of '" + roleRepr.getAttributes().get(PILOT_ROLE).getFirst() + "'");

        return roleRepr;
    }

    /**
     * Convert RoleRepresentationDTO to UserRoleDTO
     *
     * @param roleRepresentationDTO : Keycloak Role Representation
     * @return UserRoleDTO
     */
    public static UserRoleDTO toUserRoleDTO(RoleRepresentationDTO roleRepresentationDTO) {
        return UserRoleDTO.builder()
                .id(roleRepresentationDTO.getId())
                .name(roleRepresentationDTO.getName() != null ? roleRepresentationDTO.getName() : null)
                .pilotCode(roleRepresentationDTO.getAttributes() != null && roleRepresentationDTO.getAttributes().containsKey(PILOT_CODE) && !roleRepresentationDTO.getAttributes().get(PILOT_CODE).isEmpty() ? PilotCode.valueOf(roleRepresentationDTO.getAttributes().get(PILOT_CODE).getFirst()) : null)
                .pilotRole(roleRepresentationDTO.getAttributes() != null && roleRepresentationDTO.getAttributes().containsKey(PILOT_ROLE) && !roleRepresentationDTO.getAttributes().get(PILOT_ROLE).isEmpty() ? PilotRole.valueOf(roleRepresentationDTO.getAttributes().get(PILOT_ROLE).getFirst()) : null)
                .build();
    }

  //   /**
  //  * Convert a RoleRepresentationDTO to a list of UserRoleDTO in case the same role has multiple
  //  * pilot codes and pilot roles
  //  *
  //  * @param roleRepresentationDTO : RoleRepresentationDTO
  //  * @return List<UserRoleDTO>
  //  */
  // public static List<UserRoleDTO> fromRoleRepresentation(
  //   RoleRepresentationDTO roleRepresentationDTO) {

  // if (roleRepresentationDTO.getAttributes() != null && roleRepresentationDTO.getName() != null
  //     && roleRepresentationDTO.getAttributes().containsKey(PILOT_CODE)
  //     && !roleRepresentationDTO.getAttributes().get(PILOT_CODE).isEmpty()
  //     && roleRepresentationDTO.getAttributes().containsKey(PILOT_ROLE)
  //     && !roleRepresentationDTO.getAttributes().get(PILOT_ROLE).isEmpty()) {

  //   List<String> pilotCodes = roleRepresentationDTO.getAttributes().get(PILOT_CODE);
  //   List<String> pilotRoles = roleRepresentationDTO.getAttributes().get(PILOT_ROLE);

  //   return IntStream.range(0, pilotCodes.size())
  //       .mapToObj(index -> UserRoleDTO.builder()
  //         .id(roleRepresentationDTO.getId())
  //         .name(roleRepresentationDTO.getName())
  //         .pilotCode(PilotCode.valueOf(pilotCodes.get(index)))
  //         .pilotRole(PilotRole.valueOf(pilotRoles.get(index))).build())
  //       .toList();
  // }

  // // Return an empty list if the attributes are not present and all values are present
  // return Collections.emptyList();
}
