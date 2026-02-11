package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.admin.dto.auditDTO.AuditLogResponseDTO;
import com.auth.security.auth_security_app.admin.service.Interface.AuditLogService;
import lombok.RequiredArgsConstructor;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/audit")
@RequiredArgsConstructor
public class AuditLogController {

    private final AuditLogService auditLogService;

    /**
     * Get paginated audit logs
     * Supports:
     *  - page
     *  - size
     *  - sort (ASC/DESC)
     *  - actorUserId filter (optional)
     *  - action filter (optional)
     */
    @GetMapping
    public ResponseEntity<Page<AuditLogResponseDTO>> getAuditLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "timestamp,desc") String sort,
            @RequestParam(required = false) Long actorUserId,
            @RequestParam(required = false) String action
    ) {

        // Parse sort format: "timestamp,desc"
        String[] parts = sort.split(",");
        String sortField = parts[0];
        Sort.Direction direction = parts.length > 1 && parts[1].equalsIgnoreCase("asc")
                ? Sort.Direction.ASC
                : Sort.Direction.DESC;

        PageRequest pageable = PageRequest.of(page, size, Sort.by(direction, sortField));

        Page<AuditLogResponseDTO> logs = auditLogService.getAuditLogs(actorUserId, action, pageable);

        return ResponseEntity.ok(logs);
    }

    /**
     * Get specific audit log by ID
     */
    @GetMapping("/{id}")
    public ResponseEntity<AuditLogResponseDTO> getById(@PathVariable Long id) {
        return ResponseEntity.ok(auditLogService.getById(id));
    }
}
