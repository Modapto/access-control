package gr.atc.modapto.service;

import gr.atc.modapto.dto.PilotDTO;
import gr.atc.modapto.dto.UserDTO;
import gr.atc.modapto.dto.UserRoleDTO;
import jakarta.validation.Valid;

import java.util.List;

public interface IAdminService {

    List<String> retrieveAllPilotRoles(String token, boolean isSuperAdmin);

    List<String> retrieveAllPilots(String token);

    List<UserRoleDTO> retrieveAllUserRoles(String token, String pilot);

    boolean assignUserRoleToPilot(String userRole, String pilotCode, String token);

    boolean createUserRole(String tokenValue, @Valid UserRoleDTO pilotRole);

    UserRoleDTO retrieveUserRole(String tokenValue, String roleName);

    boolean deleteUserRole(String tokenValue, String roleName);

    boolean updateUserRole(String tokenValue, UserRoleDTO userRole, String existingRoleName);

    List<String> retrieveAllUserRolesByPilot(String tokenValue, String pilotCode);

    List<UserDTO> retrieveAllUsersByUserRole(String tokenValue, String userRole);

    boolean createNewPilot(String tokenValue, PilotDTO pilotData);
}

