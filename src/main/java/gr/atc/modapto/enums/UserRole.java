package gr.atc.modapto.enums;

/*
 * Enum for User Roles
 */
public enum UserRole {
    ROBOT_PROGRAMMER("ROBOT_PROGRAMMER"),
    VIRTUAL_COMMISIONING_ENGINEER("VIRTUAL_COMMISIONING_ENGINEER"),
    ROBOT_SIMULATION_USER("ROBOT_SIMULATION_USER"),
    PROCESS_ENGINEER("PROCESS_ENGINEER"),
    PLANT_OPERATOR("PLANT_OPERATOR"),
    TECHNICIAN("TECHNICIAN"),
    PRODUCTION_SCHEDULING_TEAM_MEMBER("PRODUCTION_SCHEDULING_TEAM_MEMBER"),
    MAINTENANCE_ENGINEER("MAINTENANCE_ENGINEER"),
    INNOVATION_ENGINEER("INNOVATION_ENGINEER"),
    OPERATOR("OPERATOR"),
    SHOP_FLOOR_MANAGER("SHOP_FLOOR_MANAGER"),
    PLANT_MANAGER("PLANT_MANAGER"),
    PRODUCTION_MANAGER("PRODUCTION_MANAGER"),
    LOGISTICS_MANAGER("LOGISTICS_MANAGER"),
    PRODUCTION_SCHEDULER("PRODUCTION_SCHEDULER"),
    DESIGN_EXPERT("DESIGN_EXPERT"),
    AUTOMATION_MANAGER("AUTOMATION_MANAGER"),
    SUPER_ADMIN("SUPER_ADMIN"),
    NONE("NONE");

    private final String role;

    UserRole(final String role) {
        this.role = role;
    }

    @Override
    public String toString() {
        return role;
    }
}