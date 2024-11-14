package gr.atc.modapto.controller;

import gr.atc.modapto.service.AdminService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RequestMapping("api/admin")
@AllArgsConstructor
@RestController
@Slf4j
public class AdminController {

    private final AdminService adminService;

    /**
     * GET all Keycloak User Roles
     * @param jwt : JWT Token
     * @return List<String> : List of User Roles
     */
    @Operation(summary = "Retrieve all user roles from Keycloak")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User roles retrieved successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token")
    })
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    @GetMapping("/roles")
    public ResponseEntity<ApiResponseInfo<List<String>>> getAllUserRoles(@AuthenticationPrincipal Jwt jwt) {
        return new ResponseEntity<>(ApiResponseInfo.success(adminService.retrieveAllUserRoles(jwt.getTokenValue()), "User roles retrieved successfully"), HttpStatus.OK);
    }

    /**
     * GET all Keycloak Pilots
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
