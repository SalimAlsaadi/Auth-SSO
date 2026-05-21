package com.auth.security.auth_security_app.admin.service.Implementation;

import com.auth.security.auth_security_app.admin.entity.ClientEntity;
import com.auth.security.auth_security_app.admin.entity.UserClientEntity;
import com.auth.security.auth_security_app.admin.entity.UserEntity;
import com.auth.security.auth_security_app.admin.entity.UserRoleEntity;
import com.auth.security.auth_security_app.admin.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class ClientAwareAuthenticationProvider extends DaoAuthenticationProvider {

    private static final String SAS_UI_CLIENT_ID = "sas-admin-ui";

    private static final String SESSION_REQUESTED_CLIENT_ID = "REQUESTED_CLIENT_ID";
    private static final String SESSION_ACTIVE_MANAGED_CLIENT = "ACTIVE_MANAGED_CLIENT";
    private static final String SESSION_ALLOWED_MANAGED_CLIENTS = "ALLOWED_MANAGED_CLIENTS";
    private static final String SESSION_IS_SAS_ADMIN = "IS_SAS_ADMIN";
    private static final String SESSION_IS_CLIENT_ADMIN = "IS_CLIENT_ADMIN";

    private final UserRepository userRepository;

    public ClientAwareAuthenticationProvider(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        Authentication result = super.authenticate(authentication);

        String username = authentication.getName();
        String requestedClientId = resolveRequestedClientId();

        // No client_id found:
        // allow normal login flow, but do not assign any client context yet.
        if (requestedClientId == null || requestedClientId.isBlank()) {
            clearClientContextIfPossible();
            return result;
        }

        UserEntity user = userRepository.findByUsernameWithRolesAndClients(username)
                .orElseThrow(() -> new BadCredentialsException("Invalid username or password"));

        Set<String> roleNames = extractRoleNames(user);
        Set<String> allowedClientIds = extractAllowedClientIds(user);

        boolean isSasAdmin = isSasAdmin(roleNames);
        boolean isAnyClientAdmin = isAnyClientAdmin(roleNames);
        boolean hasExactClientAccess = allowedClientIds.contains(requestedClientId);
        boolean hasAnyManagedClient = !allowedClientIds.isEmpty();

        boolean allowed;

        if (SAS_UI_CLIENT_ID.equalsIgnoreCase(requestedClientId)) {
            // SAS UI access rules:
            // 1) SAS_ADMIN => allowed to all
            // 2) exact sas-admin-ui client mapping => allowed
            // 3) any client-admin role + at least one allowed business client => allowed
            allowed = isSasAdmin || hasExactClientAccess || (isAnyClientAdmin && hasAnyManagedClient);
        } else {
            // Normal client application access rules:
            // 1) SAS_ADMIN => allowed
            // 2) exact client mapping => allowed
            allowed = isSasAdmin || hasExactClientAccess;
        }

        if (!allowed) {
            clearClientContextIfPossible();
            throw new BadCredentialsException("This user cannot login in SAS system");
        }

        storeClientContext(requestedClientId, allowedClientIds, isSasAdmin, isAnyClientAdmin);

        return result;
    }

    private Set<String> extractRoleNames(UserEntity user) {
        if (user.getRoles() == null) {
            return Set.of();
        }

        return user.getRoles().stream()
                .map(UserRoleEntity::getRole)
                .filter(Objects::nonNull)
                .map(role -> role.getRoleName())
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private Set<String> extractAllowedClientIds(UserEntity user) {
        if (user.getClients() == null) {
            return Set.of();
        }

        return user.getClients().stream()
                .map(UserClientEntity::getClient)
                .filter(Objects::nonNull)
                .map(ClientEntity::getOauthClientId)
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private boolean isSasAdmin(Set<String> roleNames) {
        return roleNames.stream()
                .anyMatch(role -> "SAS_ADMIN".equalsIgnoreCase(role));
    }

    private boolean isAnyClientAdmin(Set<String> roleNames) {
        return roleNames.stream().anyMatch(this::isClientAdminRoleName);
    }

    private boolean isClientAdminRoleName(String roleName) {
        if (roleName == null || roleName.isBlank()) {
            return false;
        }

        String normalized = roleName.trim().toUpperCase();

        // Exclude SAS admin from client-admin detection
        if ("SAS_ADMIN".equals(normalized)) {
            return false;
        }

        // Accept generic client admin
        if ("CLIENT_ADMIN".equals(normalized)) {
            return true;
        }

        // Accept client-specific admin roles like:
        // AQARK_ADMIN, TRA_ADMIN, XYZ_ADMIN
        return normalized.endsWith("_ADMIN");
    }

    private void storeClientContext(String requestedClientId,
                                    Set<String> allowedClientIds,
                                    boolean isSasAdmin,
                                    boolean isAnyClientAdmin) {

        ServletRequestAttributes attrs =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

        if (attrs == null) {
            return;
        }

        HttpServletRequest request = attrs.getRequest();
        HttpSession session = request.getSession(true);

        session.setAttribute(SESSION_REQUESTED_CLIENT_ID, requestedClientId);
        session.setAttribute(SESSION_IS_SAS_ADMIN, isSasAdmin);
        session.setAttribute(SESSION_IS_CLIENT_ADMIN, isAnyClientAdmin);

        List<String> managedClients = allowedClientIds.stream().toList();
        session.setAttribute(SESSION_ALLOWED_MANAGED_CLIENTS, managedClients);

        if (SAS_UI_CLIENT_ID.equalsIgnoreCase(requestedClientId)) {
            if (isSasAdmin) {
                session.setAttribute(SESSION_ACTIVE_MANAGED_CLIENT, "ALL");
                return;
            }

            // Client admin logged into SAS UI
            if (isAnyClientAdmin) {
                if (managedClients.size() == 1) {
                    session.setAttribute(SESSION_ACTIVE_MANAGED_CLIENT, managedClients.get(0));
                } else if (managedClients.size() > 1) {
                    // Frontend should ask user to choose one client
                    session.setAttribute(SESSION_ACTIVE_MANAGED_CLIENT, null);
                } else {
                    session.setAttribute(SESSION_ACTIVE_MANAGED_CLIENT, null);
                }
                return;
            }

            // Exact mapping to sas-admin-ui but not admin role
            if (allowedClientIds.contains(SAS_UI_CLIENT_ID)) {
                session.setAttribute(SESSION_ACTIVE_MANAGED_CLIENT, SAS_UI_CLIENT_ID);
                return;
            }

            session.setAttribute(SESSION_ACTIVE_MANAGED_CLIENT, null);
            return;
        }

        // Normal client login
        session.setAttribute(SESSION_ACTIVE_MANAGED_CLIENT, requestedClientId);
    }

    private void clearClientContextIfPossible() {
        ServletRequestAttributes attrs =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

        if (attrs == null) {
            return;
        }

        HttpServletRequest request = attrs.getRequest();
        HttpSession session = request.getSession(false);

        if (session == null) {
            return;
        }

        session.removeAttribute(SESSION_REQUESTED_CLIENT_ID);
        session.removeAttribute(SESSION_ACTIVE_MANAGED_CLIENT);
        session.removeAttribute(SESSION_ALLOWED_MANAGED_CLIENTS);
        session.removeAttribute(SESSION_IS_SAS_ADMIN);
        session.removeAttribute(SESSION_IS_CLIENT_ADMIN);
    }

    private String resolveRequestedClientId() {
        ServletRequestAttributes attrs =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

        if (attrs == null) {
            return null;
        }

        HttpServletRequest request = attrs.getRequest();

        // 1) direct parameter from request
        String clientId = trimToNull(request.getParameter("client_id"));
        if (clientId != null) {
            return clientId;
        }

        // 2) saved request from OAuth2 redirect flow
        HttpSession session = request.getSession(false);
        if (session != null) {
            Object saved = session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
            if (saved instanceof DefaultSavedRequest dsr) {
                String[] values = dsr.getParameterValues("client_id");
                if (values != null && values.length > 0) {
                    return trimToNull(values[0]);
                }
            }
        }

        return null;
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}