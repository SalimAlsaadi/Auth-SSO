package com.auth.security.auth_security_app.admin.dto.dashboardDTO;

import lombok.Data;

@Data
public class DashboardResponseDTO {
    private long totalUsers;
    private long activeUsers;
    private long totalRoles;
    private long totalPermissions;
    private long totalClients;
}
