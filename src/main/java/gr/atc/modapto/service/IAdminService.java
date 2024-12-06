package gr.atc.modapto.service;

import gr.atc.modapto.dto.UserRoleDTO;
import jakarta.validation.Valid;

import java.util.List;

public interface IAdminService {

    List<String> retrieveAllUserRoles(String token, boolean isSuperAdmin);

    List<String> retrieveAllPilots(String token);

    List<String> retrieveAllPilotRoles(String token);

    boolean assignUserRoleToPilot(String userRole, String pilotCode, String clientId, String token);

    boolean createUserRole(String tokenValue, @Valid UserRoleDTO pilotRole);

    UserRoleDTO retrieveUserRole(String tokenValue, String roleName);

    boolean deleteUserRole(String tokenValue, String roleName);

    boolean updateUserRole(String tokenValue, UserRoleDTO userRole, String existingRoleName);
}

