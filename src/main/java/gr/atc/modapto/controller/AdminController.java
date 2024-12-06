package gr.atc.modapto.controller;

import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import gr.atc.modapto.dto.UserRoleDTO;
import gr.atc.modapto.enums.PilotRole;
import gr.atc.modapto.service.AdminService;
import gr.atc.modapto.util.JwtUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequestMapping("api/admin")
@AllArgsConstructor
@RestController
@Slf4j
public class AdminController {
    /**
     * Pilot Role: Role that a user can have inside the organization dependind on the . Generic type of user. Can be User, Admin, Super Admin
     * User Role: Specific role a use can have inside an organization
     * Pilot Code: The abbreviation of the Pilot
     */

    private final AdminService adminService;

    private static final String INVALID_TOKEN = "Token inserted is invalid. It does not contain any information about the user role or the pilot";

    private static final String UNAUTHORIZED_ACTION = "Unauthorized action";

    /**
     * GET all Keycloak User Roles or filter by Pilot
     *
     * @param jwt : JWT Token
     * @return List<String> : List of User Roles
     */
    @Operation(summary = "Retrieve all user roles from Keycloak")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User roles retrieved successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the user role")
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @GetMapping("/roles")
    public ResponseEntity<ApiResponseInfo<List<String>>> getAllUserRoles(@AuthenticationPrincipal Jwt jwt) {
      // Validate token proper format
      String role = JwtUtils.extractPilotRole(jwt);
      if (role == null)
          return new ResponseEntity<>(ApiResponseInfo.error("Token inserted is invalid. It does not contain any information about the user role"), HttpStatus.FORBIDDEN);

      // Set the flag to true or false according to the Role of User
      boolean isSuperAdmin = !role.equals(PilotRole.ADMIN.toString());

      return new ResponseEntity<>(ApiResponseInfo.success(adminService.retrieveAllUserRoles(jwt.getTokenValue(), isSuperAdmin), "User roles retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Create a new User Role in Keycloak
     *
     * @param jwt : JWT Token
     * @return Success message or Failure Message
     */
    @Operation(summary = "Create a new User Role")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User role created successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the user role or the pilot"),
            @ApiResponse(responseCode = "500", description = "Unable to create and store the new role")
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @PostMapping("/roles/create")
    public ResponseEntity<ApiResponseInfo<Void>> createNewUserRole(@AuthenticationPrincipal Jwt jwt, @RequestBody UserRoleDTO userRole) {
        // Validate token proper format
        String role = JwtUtils.extractPilotRole(jwt);
        String pilot = JwtUtils.extractPilotCode(jwt);

        // Check if JWT contains the proper information
        if (StringUtils.isAnyBlank(role, pilot))
            return new ResponseEntity<>(ApiResponseInfo.error(INVALID_TOKEN), HttpStatus.FORBIDDEN);

        // Validate that all fields are provided as body
        if (userRole == null || userRole.getPilotRole() == null || userRole.getName() == null || userRole.getPilotCode() == null)
            return new ResponseEntity<>(ApiResponseInfo.error("All fields of roles must be inserted (Name, Pilot Code, Pilot Type)", "Missing fields"), HttpStatus.BAD_REQUEST);

        // Validate that Admin can only create a role inside his/her organization
        if (role.equals(PilotRole.ADMIN.toString()) && !pilot.equals(userRole.getPilotCode().toString()))
            return new ResponseEntity<>(ApiResponseInfo.error(UNAUTHORIZED_ACTION, "User of role 'ADMIN' can only create a new role only inside their organization"), HttpStatus.FORBIDDEN);

        // Create User Role in Keycloak
        if (adminService.createUserRole(jwt.getTokenValue(), userRole))
            return new ResponseEntity<>(ApiResponseInfo.success(null,"User role created successfully"), HttpStatus.CREATED);
        else
            return new ResponseEntity<>(ApiResponseInfo.error("Unable to create and store the new user role"), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Delete a User Role in Keycloak
     *
     * @param jwt : JWT Token
     * @param roleName : Name of the Role
     * @return Success message or Failure Message
     */
    @Operation(summary = "Delete a User Role")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User role deleted successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the user role or the pilot"),
            @ApiResponse(responseCode = "403", description = "User of role 'ADMIN' can only delete a role only inside their organization"),
            @ApiResponse(responseCode = "404", description = "User role not found in Keycloak"),
            @ApiResponse(responseCode = "500", description = "Unable to to delete the user role")
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @DeleteMapping("/roles/{roleName}")
    public ResponseEntity<ApiResponseInfo<Void>> deleteUserRole(@AuthenticationPrincipal Jwt jwt, @PathVariable String roleName) {
        // Validate token proper format
        String role = JwtUtils.extractPilotRole(jwt);
        String pilot = JwtUtils.extractPilotCode(jwt);

        // Check if JWT contains the proper information
        if (StringUtils.isAnyBlank(role, pilot))
            return new ResponseEntity<>(ApiResponseInfo.error(INVALID_TOKEN), HttpStatus.FORBIDDEN);

        // Fetch User Role given the roleId (if exists)
        UserRoleDTO userRole = adminService.retrieveUserRole(jwt.getTokenValue(), roleName);

        // Validate that Admin can only create a role inside his/her organization
        if (role.equals(PilotRole.ADMIN.toString()) && !pilot.equals(userRole.getPilotCode().toString()))
            return new ResponseEntity<>(ApiResponseInfo.error(UNAUTHORIZED_ACTION, "User of role 'ADMIN' can only delete a role only inside their organization"), HttpStatus.FORBIDDEN);

        // Delete a User Role in Keycloak
        if (adminService.deleteUserRole(jwt.getTokenValue(), roleName))
            return new ResponseEntity<>(ApiResponseInfo.success(null,"User role deleted successfully"), HttpStatus.OK);
        else
            return new ResponseEntity<>(ApiResponseInfo.error("Unable to delete the user role", "Role not found or an internal error occured"), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Retrievea a User Role in Keycloak
     *
     * @param jwt : JWT Token
     * @param roleName : Name of the Role
     * @return UserRoleDTO
     */
    @Operation(summary = "Retrieve a User Role")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User role retrieved successfully", content = @Content(schema = @Schema(implementation = UserRoleDTO.class))),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "404", description = "User role not found in Keycloak"),
            @ApiResponse(responseCode = "500", description = "Unable to retrive the user role")
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @GetMapping("/roles/{roleName}")
    public ResponseEntity<ApiResponseInfo<UserRoleDTO>> retrieveUserRole(@AuthenticationPrincipal Jwt jwt, @PathVariable String roleName) {
            return new ResponseEntity<>(ApiResponseInfo.success(adminService.retrieveUserRole(jwt.getTokenValue(), roleName),"User role retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Update a User Role in Keycloak
     *
     * @param jwt : JWT Token
     * @param roleName : Name of the Role
     * @return Success message or Failure Message
     */
    @Operation(summary = "Update a User Role")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User role updated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the user role or the pilot"),
            @ApiResponse(responseCode = "403", description = "User of role 'ADMIN' can only update a role only inside their organization"),
            @ApiResponse(responseCode = "403", description = "User of role 'SUPER_ADMIN' can convert a pilot role into 'SUPER_ADMIN'"),
            @ApiResponse(responseCode = "404", description = "User role not found in Keycloak"),
            @ApiResponse(responseCode = "500", description = "Unable to create and store the new role")
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @PutMapping("/roles/{roleName}")
    public ResponseEntity<ApiResponseInfo<Void>> updateUserRole(@AuthenticationPrincipal Jwt jwt, @PathVariable String roleName, @RequestBody UserRoleDTO userRole) {
        // Validate token proper format
        String role = JwtUtils.extractPilotRole(jwt);
        String pilot = JwtUtils.extractPilotCode(jwt);

        // Check if JWT contains the proper information
        if (StringUtils.isAnyBlank(role, pilot))
            return new ResponseEntity<>(ApiResponseInfo.error(INVALID_TOKEN), HttpStatus.FORBIDDEN);

        // Validate the only Super-Admins can update Role information to Super-Admin
        if (userRole.getPilotRole() != null && !role.equals(PilotRole.SUPER_ADMIN.toString()) && userRole.getPilotRole().equals(PilotRole.SUPER_ADMIN))
            return new ResponseEntity<>(ApiResponseInfo.error(UNAUTHORIZED_ACTION, "User of role 'SUPER_ADMIN' can convert a pilot role into 'SUPER_ADMIN'"), HttpStatus.FORBIDDEN);

        // Validate that Admin can only create a role inside his/her organization
        if (userRole.getPilotCode() != null && role.equals(PilotRole.ADMIN.toString()) && !pilot.equals(userRole.getPilotCode().toString()))
            return new ResponseEntity<>(ApiResponseInfo.error(UNAUTHORIZED_ACTION, "User of role 'ADMIN' can only update a role only inside their organization"), HttpStatus.FORBIDDEN);

        // Create User Role in Keycloak
        if (adminService.updateUserRole(jwt.getTokenValue(), userRole, roleName))
            return new ResponseEntity<>(ApiResponseInfo.success(null,"User role updated successfully"), HttpStatus.OK);
        else
            return new ResponseEntity<>(ApiResponseInfo.error("Unable to update the user role","Role not found or an internal error occured"), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * GET all Keycloak Pilots
     *
     * @param jwt : JWT Token
     * @return List<String> : List of Pilots
     */
    @Operation(summary = "Retrieve all pilots from Keycloak")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Pilot codes retrieved successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token")
    })
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    @GetMapping("/pilots")
    public ResponseEntity<ApiResponseInfo<List<String>>> getAllPilots(@AuthenticationPrincipal Jwt jwt) {
        return new ResponseEntity<>(ApiResponseInfo.success(adminService.retrieveAllPilots(jwt.getTokenValue()), "Pilot codes retrieved successfully"), HttpStatus.OK);
    }

    /**
     * GET all Keycloak Pilot Roles
     *
     * @param jwt : JWT Token
     * @return List<String> : List of Pilot Roles
     */
    @Operation(summary = "Retrieve all pilot roles from Keycloak")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Pilot roles retrieved successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token")
    })
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    @GetMapping("/pilot-roles")
    public ResponseEntity<ApiResponseInfo<List<String>>> getAllPilotRoles(@AuthenticationPrincipal Jwt jwt) {
        return new ResponseEntity<>(ApiResponseInfo.success(adminService.retrieveAllPilotRoles(jwt.getTokenValue()), "Pilot roles retrieved successfully"), HttpStatus.OK);
    }


}
