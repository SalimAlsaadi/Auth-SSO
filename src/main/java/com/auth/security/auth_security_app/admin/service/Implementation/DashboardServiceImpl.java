package com.auth.security.auth_security_app.admin.service.Implementation;

import com.auth.security.auth_security_app.admin.dto.dashboardDTO.DashboardResponseDTO;
import com.auth.security.auth_security_app.admin.repository.*;

import com.auth.security.auth_security_app.admin.service.Interface.DashboardService;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DashboardServiceImpl implements DashboardService {

    private final UserRepository userRepo;
    private final RoleRepository roleRepo;
    private final PermissionRepository permissionRepo;
    private final JdbcTemplate jdbc;

    @Override
    public DashboardResponseDTO getStatistics() {

        long clientCount = jdbc.queryForObject(
                "SELECT COUNT(*) FROM oauth2_registered_client",
                Long.class
        ) ;

        DashboardResponseDTO dto = new DashboardResponseDTO();
        dto.setTotalUsers(userRepo.count());
        dto.setActiveUsers(userRepo.countByEnabled(true));
        dto.setTotalRoles(roleRepo.count());
        dto.setTotalPermissions(permissionRepo.count());
        dto.setTotalClients(clientCount);

        return dto;
    }
}
