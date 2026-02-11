package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.admin.dto.dashboardDTO.DashboardResponseDTO;
import com.auth.security.auth_security_app.admin.service.Interface.DashboardService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/dashboard")
@RequiredArgsConstructor
public class DashboardController {

    private final DashboardService dashboardService;

    @GetMapping
    @PreAuthorize("hasRole('SAS_ADMIN")
    public ResponseEntity<DashboardResponseDTO> getStats(){
        return ResponseEntity.ok(dashboardService.getStatistics());
    }
}
