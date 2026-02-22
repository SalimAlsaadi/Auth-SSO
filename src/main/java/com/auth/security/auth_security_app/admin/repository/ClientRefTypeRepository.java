//package com.auth.security.auth_security_app.admin.repository;
//
//import com.auth.security.auth_security_app.admin.entity.ClientRefTypeEntity;
//import org.springframework.data.jpa.repository.JpaRepository;
//import org.springframework.stereotype.Repository;
//
//import java.util.List;
//
//@Repository
//public interface ClientRefTypeRepository extends JpaRepository<ClientRefTypeEntity, Integer> {
//
//    List<ClientRefTypeEntity> findByClient_OauthClientId(String oauthClientId);
//
//    List<ClientRefTypeEntity> findByClient_Id(Integer clientId);
//
//    boolean existsByClient_IdAndRefTypeName(Integer clientId, String refTypeName);
//}
