package gr.atc.modapto.controller;

import java.util.List;

import gr.atc.modapto.dto.PilotDTO;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import gr.atc.modapto.dto.UserDTO;
import gr.atc.modapto.dto.UserRoleDTO;
import gr.atc.modapto.enums.PilotRole;
import gr.atc.modapto.service.IAdminService;
import gr.atc.modapto.util.JwtUtils;
import gr.atc.modapto.validation.ValidPilotCode;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.extern.slf4j.Slf4j;

@RequestMapping("api/admin")
@RestController
@AllArgsConstructor
@Slf4j
public class AdminController {
    /**
     * Pilot Role: Role that a user can have inside the organization dependind on the . Generic type of user. Can be User, Admin, Super Admin
     * User Role: Specific role a use can have inside an organization
     * Pilot Code: The abbreviation of the Pilot
     */
    private final IAdminService adminService;

    private static final String INVALID_TOKEN = "Token inserted is invalid. It does not contain any information about the user role or the pilot";

    private static final String UNAUTHORIZED_ACTION = "Unauthorized action";

    private static final String USER_FORBIDDEN = "User of role 'USER' can not retrieve information for user roles";

    /**
     * GET all Keycloak Pilot Roles or filter by Pilot
     *
     * @param jwt : JWT Token
     * @return List<String> : List of Pilot Roles
     */
    @Operation(summary = "Retrieve all pilot roles from Keycloak", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User roles retrieved successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the user role")
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @GetMapping("/pilot-roles")
    public ResponseEntity<BaseResponse<List<String>>> getAllPilotRoles(@AuthenticationPrincipal Jwt jwt) {
      // Validate token proper format
      String role = JwtUtils.extractPilotRole(jwt);
      if (role == null)
          return new ResponseEntity<>(BaseResponse.error("Token inserted is invalid. It does not contain any information about the user role"), HttpStatus.FORBIDDEN);

      // Set the flag to true or false according to the Role of User
      boolean isSuperAdmin = !role.equalsIgnoreCase(PilotRole.ADMIN.toString());

      return new ResponseEntity<>(BaseResponse.success(adminService.retrieveAllPilotRoles(jwt.getTokenValue(), isSuperAdmin), "Pilot roles retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Create a new User Role in Keycloak
     *
     * @param jwt : JWT Token
     * @return Success message or Failure Message
     */
    @Operation(summary = "Create a new User Role", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User role created successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "400", description = "Invalid input data"),
            @ApiResponse(responseCode = "400", description = "Missing fields"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the user role or the pilot"),
            @ApiResponse(responseCode = "409", description = "User role already exists in Keycloak"),
            @ApiResponse(responseCode = "500", description = "Unable to create and store the new role")
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @PostMapping("/roles/create")
    public ResponseEntity<BaseResponse<Void>> createNewUserRole(@AuthenticationPrincipal Jwt jwt, @RequestBody UserRoleDTO userRole) {

        // Validate that all fields are provided as body
        if (userRole == null || userRole.getPilotRole() == null || userRole.getName() == null || userRole.getPilotCode() == null)
          return new ResponseEntity<>(BaseResponse.error("Missing fields", "All fields of roles must be inserted (Name, Pilot Code, Pilot Type)"), HttpStatus.BAD_REQUEST);

        // Ensure data don't contain spaces
        if (userRole.getName().contains(" "))
          return new ResponseEntity<>(BaseResponse.error("Invalid input data","Username or User Role cannot contain spaces!"),
                HttpStatus.BAD_REQUEST);
      
        // Validate token proper format
        String role = JwtUtils.extractPilotRole(jwt);
        String pilot = JwtUtils.extractPilotCode(jwt);

        // Check if JWT contains the proper information
        if (StringUtils.isAnyBlank(role, pilot))
            return new ResponseEntity<>(BaseResponse.error(INVALID_TOKEN), HttpStatus.FORBIDDEN);

        // Convert the Name to Upper Case if not already defined
        userRole.setName(userRole.getName().toUpperCase());

        // Validate that Admin can only create a role inside his/her organization
        if (role.equalsIgnoreCase(PilotRole.ADMIN.toString()) && !pilot.equalsIgnoreCase(userRole.getPilotCode().toString()))
            return new ResponseEntity<>(BaseResponse.error(UNAUTHORIZED_ACTION, "User of role 'ADMIN' can only create a new role only inside their organization"), HttpStatus.FORBIDDEN);

        // Create User Role in Keycloak
        if (adminService.createUserRole(jwt.getTokenValue(), userRole))
            return new ResponseEntity<>(BaseResponse.success(null,"User role created successfully"), HttpStatus.CREATED);
        else
            return new ResponseEntity<>(BaseResponse.error("Unable to create and store the new user role"), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Delete a User Role in Keycloak
     *
     * @param jwt : JWT Token
     * @param roleName : Name of the Role
     * @return Success message or Failure Message
     */
    @Operation(summary = "Delete a User Role", security = @SecurityRequirement(name = "bearerToken"))
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
    public ResponseEntity<BaseResponse<Void>> deleteUserRole(@AuthenticationPrincipal Jwt jwt, @PathVariable String roleName) {
        // Validate token proper format
        String role = JwtUtils.extractPilotRole(jwt);
        String pilot = JwtUtils.extractPilotCode(jwt);

        // Check if JWT contains the proper information
        if (StringUtils.isAnyBlank(role, pilot))
            return new ResponseEntity<>(BaseResponse.error(INVALID_TOKEN), HttpStatus.FORBIDDEN);

        // Fetch User Role given the roleId (if exists)
        UserRoleDTO userRole = adminService.retrieveUserRole(jwt.getTokenValue(), roleName.toUpperCase());

        // Validate that Admin can only create a role inside his/her organization
        if (role.equalsIgnoreCase(PilotRole.ADMIN.toString()) && !pilot.equalsIgnoreCase(userRole.getPilotCode().toString()))
            return new ResponseEntity<>(BaseResponse.error(UNAUTHORIZED_ACTION, "User of role 'ADMIN' can only delete a role only inside their organization"), HttpStatus.FORBIDDEN);

        // Delete a User Role in Keycloak
        if (adminService.deleteUserRole(jwt.getTokenValue(), roleName.toUpperCase()))
            return new ResponseEntity<>(BaseResponse.success(null,"User role deleted successfully"), HttpStatus.OK);
        else
            return new ResponseEntity<>(BaseResponse.error("Unable to delete the user role", "Role not found or an internal error occured"), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Retrieve a User Role in Keycloak
     *
     * @param jwt : JWT Token
     * @param roleName : Name of the Role
     * @return UserRoleDTO
     */
    @Operation(summary = "Retrieve a User Role", security = @SecurityRequirement(name = "bearerToken"))
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
    public ResponseEntity<BaseResponse<UserRoleDTO>> retrieveUserRole(@AuthenticationPrincipal Jwt jwt, @PathVariable String roleName) {
            return new ResponseEntity<>(BaseResponse.success(adminService.retrieveUserRole(jwt.getTokenValue(), roleName.toUpperCase()),"User role retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Update a User Role in Keycloak
     *
     * @param jwt : JWT Token
     * @param roleName : Name of the Role
     * @return Success message or Failure Message
     */
    @Operation(summary = "Update a User Role", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User role updated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the user role or the pilot"),
            @ApiResponse(responseCode = "403", description = "User of role 'ADMIN' can only update a role only inside their organization"),
            @ApiResponse(responseCode = "403", description = "User of role 'SUPER_ADMIN' can only convert a pilot role into 'SUPER_ADMIN'"),
            @ApiResponse(responseCode = "404", description = "User role not found in Keycloak"),
            @ApiResponse(responseCode = "500", description = "Unable to create and store the new role")
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @PutMapping("/roles/{roleName}")
    public ResponseEntity<BaseResponse<Void>> updateUserRole(@AuthenticationPrincipal Jwt jwt, @PathVariable String roleName, @RequestBody UserRoleDTO userRole) {
        // Validate token proper format
        String role = JwtUtils.extractPilotRole(jwt);
        String pilot = JwtUtils.extractPilotCode(jwt);

        // Check if JWT contains the proper information
        if (StringUtils.isAnyBlank(role, pilot))
            return new ResponseEntity<>(BaseResponse.error(INVALID_TOKEN), HttpStatus.FORBIDDEN);

        // Validate the only Super-Admins can update Role information to Super-Admin
        if (userRole.getPilotRole() != null && !role.equalsIgnoreCase(PilotRole.SUPER_ADMIN.toString()) && userRole.getPilotRole().equals(PilotRole.SUPER_ADMIN))
            return new ResponseEntity<>(BaseResponse.error(UNAUTHORIZED_ACTION, "User of role 'SUPER_ADMIN' can only convert a pilot role into 'SUPER_ADMIN'"), HttpStatus.FORBIDDEN);

        // Validate that Admin can only create a role inside his/her organization
        if (userRole.getPilotCode() != null && role.equalsIgnoreCase(PilotRole.ADMIN.toString()) && !pilot.equalsIgnoreCase(userRole.getPilotCode().toString()))
            return new ResponseEntity<>(BaseResponse.error(UNAUTHORIZED_ACTION, "User of role 'ADMIN' can only update a role only inside their organization"), HttpStatus.FORBIDDEN);

        // If name was given convert it to upper case if not already defined that way
        if (userRole.getName() != null)
            userRole.setName(userRole.getName().toUpperCase());

        // Create User Role in Keycloak
        if (adminService.updateUserRole(jwt.getTokenValue(), userRole, roleName.toUpperCase()))
            return new ResponseEntity<>(BaseResponse.success(null,"User role updated successfully"), HttpStatus.OK);
        else
            return new ResponseEntity<>(BaseResponse.error("Unable to update the user role","Role not found or an internal error occured"), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * GET all Keycloak Pilots
     *
     * @param jwt : JWT Token
     * @return List<String> : List of Pilots
     */
    @Operation(summary = "Retrieve all pilots from Keycloak", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Pilot codes retrieved successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token")
    })
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    @GetMapping("/pilots")
    public ResponseEntity<BaseResponse<List<String>>> getAllPilots(@AuthenticationPrincipal Jwt jwt) {
        return new ResponseEntity<>(BaseResponse.success(adminService.retrieveAllPilots(jwt.getTokenValue()), "Pilot codes retrieved successfully"), HttpStatus.OK);
    }

    /**
     * GET all Keycloak User Role Names
     *
     * @param jwt : JWT Token
     * @return List<String> : List of User Role Names
     */
    @Operation(summary = "Retrieve all user role names from Keycloak", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User roles retrieved successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the user role or the pilot"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token")
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @GetMapping("/roles/names")
    public ResponseEntity<BaseResponse<List<String>>> getAllUserRoleNames(@AuthenticationPrincipal Jwt jwt) {
        // Validate token proper format
        String role = JwtUtils.extractPilotRole(jwt);
        String pilot = JwtUtils.extractPilotCode(jwt);

        // Check if JWT contains the proper information
        if (StringUtils.isAnyBlank(role, pilot))
            return new ResponseEntity<>(BaseResponse.error(INVALID_TOKEN), HttpStatus.FORBIDDEN);

        // Create the list of String for the names of user roles
        List<String> userRoleNames = adminService.retrieveAllUserRoles(jwt.getTokenValue(), pilot.toUpperCase()).stream().map(UserRoleDTO::getName).toList();
        return new ResponseEntity<>(BaseResponse.success(userRoleNames, "User role names retrieved successfully"), HttpStatus.OK);
    }

    /**
     * GET all Keycloak User Roles
     *
     * @param jwt : JWT Token
     * @return List<UserRoleDTO> : List of User Roles
     */
    @Operation(summary = "Retrieve all user roles from Keycloak", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User roles retrieved successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the user role or the pilot"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token")
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @GetMapping("/roles")
    public ResponseEntity<BaseResponse<List<UserRoleDTO>>> getAllUserRoles(@AuthenticationPrincipal Jwt jwt) {
        // Validate token proper format
        String role = JwtUtils.extractPilotRole(jwt);
        String pilot = JwtUtils.extractPilotCode(jwt);

        // Check if JWT contains the proper information
        if (StringUtils.isAnyBlank(role, pilot))
            return new ResponseEntity<>(BaseResponse.error(INVALID_TOKEN), HttpStatus.FORBIDDEN);

        return new ResponseEntity<>(BaseResponse.success(adminService.retrieveAllUserRoles(jwt.getTokenValue(), pilot.toUpperCase()), "User roles retrieved successfully"), HttpStatus.OK);
    }

    /**
     * GET all Keycloak User Roles filtered by Pilot
     *
     * @param jwt : JWT Token
     * @param pilotCode : Pilot Code
     * @return List<String> : List of User Roles
     */
    @Operation(summary = "Retrieve all user roles from Keycloak filtered by Pilot Code", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User roles retrieved successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "User of role 'USER' can not retrieve information for user roles"),
            @ApiResponse(responseCode = "403", description = "User of role 'ADMIN' can only retrieve user roles only inside their organization"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the user role or the pilot")
    })
    @GetMapping("/roles/pilot/{pilotCode}")
    public ResponseEntity<BaseResponse<List<UserRoleDTO>>> getAllUserRolesPerPilot(@AuthenticationPrincipal Jwt jwt, @ValidPilotCode @PathVariable String pilotCode) {
        // Validate token proper format
        String role = JwtUtils.extractPilotRole(jwt);
        String pilot = JwtUtils.extractPilotCode(jwt);

        // Check if JWT contains the proper information
        if (StringUtils.isAnyBlank(role, pilot))
            return new ResponseEntity<>(BaseResponse.error(INVALID_TOKEN), HttpStatus.FORBIDDEN);

        // Refrain users from retrieving data
        if (role.equalsIgnoreCase(PilotRole.USER.toString()))
            return new ResponseEntity<>(BaseResponse.error(UNAUTHORIZED_ACTION, USER_FORBIDDEN), HttpStatus.FORBIDDEN);

        // Validate that Admin can only create a role inside his/her organization
        if (role.equalsIgnoreCase(PilotRole.ADMIN.toString()) && !pilot.equalsIgnoreCase(pilotCode))
            return new ResponseEntity<>(BaseResponse.error(UNAUTHORIZED_ACTION, "User of role 'ADMIN' can only retrieve user roles only inside their organization"), HttpStatus.FORBIDDEN);

        return new ResponseEntity<>(BaseResponse.success(adminService.retrieveAllUserRoles(jwt.getTokenValue(), pilotCode.toUpperCase()), "User roles retrieved successfully"), HttpStatus.OK);
    }
    /**
     * GET all Keycloak User Role names filtered by Pilot
     *
     * @param jwt : JWT Token
     * @param pilotCode : Pilot Code
     * @return List<String> : List of User Roles
     */
    @Operation(summary = "Retrieve all user role names from Keycloak filtered by Pilot Code", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User role names retrieved successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "User of role 'USER' can not retrieve information for user roles"),
            @ApiResponse(responseCode = "403", description = "User of role 'ADMIN' can only retrieve user roles only inside their organization"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the user role or the pilot")
    })
    @GetMapping("/roles/names/pilot/{pilotCode}")
    public ResponseEntity<BaseResponse<List<String>>> getAllUserRolesNamesPerPilot(@AuthenticationPrincipal Jwt jwt, @ValidPilotCode @PathVariable String pilotCode) {
        // Validate token proper format
        String role = JwtUtils.extractPilotRole(jwt);
        String pilot = JwtUtils.extractPilotCode(jwt);

        // Check if JWT contains the proper information
        if (StringUtils.isAnyBlank(role, pilot))
            return new ResponseEntity<>(BaseResponse.error(INVALID_TOKEN), HttpStatus.FORBIDDEN);

        // Refrain users from retrieving data
        if (role.equalsIgnoreCase(PilotRole.USER.toString()))
            return new ResponseEntity<>(BaseResponse.error(UNAUTHORIZED_ACTION, USER_FORBIDDEN), HttpStatus.FORBIDDEN);

        // Validate that Admin can only create a role inside his/her organization
        if (role.equalsIgnoreCase(PilotRole.ADMIN.toString()) && !pilot.equalsIgnoreCase(pilotCode))
            return new ResponseEntity<>(BaseResponse.error(UNAUTHORIZED_ACTION, "User of role 'ADMIN' can only retrieve user roles only inside their organization"), HttpStatus.FORBIDDEN);

        return new ResponseEntity<>(BaseResponse.success(adminService.retrieveAllUserRolesByPilot(jwt.getTokenValue(), pilotCode.toUpperCase()), "User role names retrieved successfully"), HttpStatus.OK);
    }

    /**
     * GET all users associated with a Role
     *
     * @param jwt : JWT Token
     * @param userRole : User Role
     * @return List<String> : List of User Roles
     */
    @Operation(summary = "Retrieve all users associated with a specific user role", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Users associated with the role retrieved successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "User of role 'USER' can not retrieve information for user roles"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the user role")
    })
    @GetMapping("/roles/{userRole}/users")
    public ResponseEntity<BaseResponse<List<UserDTO>>> getAllUserByUserRole(@AuthenticationPrincipal Jwt jwt, @PathVariable String userRole) {
        // Validate token proper format
        String role = JwtUtils.extractPilotRole(jwt);
        String pilot = JwtUtils.extractPilotCode(jwt);

        // Check if JWT contains the proper information
        if (StringUtils.isAnyBlank(role, pilot))
            return new ResponseEntity<>(BaseResponse.error(INVALID_TOKEN), HttpStatus.FORBIDDEN);

        // Refrain users from retrieving data
        if (role.equalsIgnoreCase(PilotRole.USER.toString()))
            return new ResponseEntity<>(BaseResponse.error(UNAUTHORIZED_ACTION, USER_FORBIDDEN), HttpStatus.FORBIDDEN);

        return new ResponseEntity<>(BaseResponse.success(adminService.retrieveAllUsersByUserRole(jwt.getTokenValue(), userRole.toUpperCase()), "Users associated with the role retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Create a new Pilot in Keycloak
     *
     * @param jwt : JWT Token
     * @return Success message or Failure Message
     */
    @Operation(summary = "Create a new Pilot / Organization", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Pilot created successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "400", description = "Invalid input data"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the user role or the pilot"),
            @ApiResponse(responseCode = "409", description = "Pilot already exists in Keycloak"),
            @ApiResponse(responseCode = "500", description = "Unable to create and store the new piloit")
    })
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    @PostMapping("/pilot")
    public ResponseEntity<BaseResponse<Void>> createNewPilotInSystem(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody PilotDTO pilotData) {
        // Validate token proper format
        String role = JwtUtils.extractPilotRole(jwt);
        String pilot = JwtUtils.extractPilotCode(jwt);

        // Check if JWT contains the proper information
        if (StringUtils.isAnyBlank(role, pilot))
            return new ResponseEntity<>(BaseResponse.error(INVALID_TOKEN), HttpStatus.FORBIDDEN);

        // Create Pilot in Keycloak
        if (adminService.createNewPilot(jwt.getTokenValue(), pilotData))
            return new ResponseEntity<>(BaseResponse.success(null,"Pilot created successfully"), HttpStatus.CREATED);
        else
            return new ResponseEntity<>(BaseResponse.error("Unable to create and store the new pilot"), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Assign a User Role to a Pilot
     *
     * @param pilotCode : Pilot Code
     * @param userRole  : User Role to assing
     * @param jwt       : JWT Token
     * @return Success message or Failure Message
     */
    @Operation(summary = "Assign User Role to specific Pilot / Organization", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User role assigned successfully to pilot"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "400", description = "Invalid / No input was given for requested resource"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the user role or the pilot"),
            @ApiResponse(responseCode = "403", description = "Unauthorized action"),
            @ApiResponse(responseCode = "404", description = "Unable to retrieve requested data"),
            @ApiResponse(responseCode = "500", description = "Unable to assign the user role to specified pilot")
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @PutMapping("/pilot/{pilotCode}/assign/role/{userRole}")
    public ResponseEntity<BaseResponse<Void>> assignUserRoleToPilot(@AuthenticationPrincipal Jwt jwt, @PathVariable String pilotCode, @PathVariable String userRole) {
        // Validate token proper format
        String role = JwtUtils.extractPilotRole(jwt);
        String pilot = JwtUtils.extractPilotCode(jwt);

        // Check if JWT contains the proper information
        if (StringUtils.isAnyBlank(role, pilot))
            return new ResponseEntity<>(BaseResponse.error(INVALID_TOKEN), HttpStatus.FORBIDDEN);

        // Retrieve Role
        UserRoleDTO existingRole = adminService.retrieveUserRole(jwt.getTokenValue(), userRole.toUpperCase());

        // Validate that User Role is not type of 'Super-Admin'
        if (existingRole.getPilotRole() != null && existingRole.getPilotRole().equals(PilotRole.SUPER_ADMIN))
            return new ResponseEntity<>(BaseResponse.error(UNAUTHORIZED_ACTION, "Role of type 'SUPER_ADMIN' can not be assigned to a pilot"), HttpStatus.FORBIDDEN);

        // Validate that Admin can only assign a role inside his/her organization
        if (existingRole.getPilotCode() != null && role.equalsIgnoreCase(PilotRole.ADMIN.toString()) && !pilotCode.equalsIgnoreCase(existingRole.getPilotCode().toString()) && !pilotCode.equalsIgnoreCase(pilot))
            return new ResponseEntity<>(BaseResponse.error(UNAUTHORIZED_ACTION, "User of role 'ADMIN' can only assign a role only inside their organization"), HttpStatus.FORBIDDEN);

        // Create Pilot in Keycloak
        if (adminService.assignUserRoleToPilot(userRole.toUpperCase(), pilotCode.toUpperCase(), jwt.getTokenValue()))
            return new ResponseEntity<>(BaseResponse.success(null,"User role assigned successfully to pilot"), HttpStatus.OK);
        else
            return new ResponseEntity<>(BaseResponse.error("Unable to assign the user role to specified pilot"), HttpStatus.INTERNAL_SERVER_ERROR);
    }

}
