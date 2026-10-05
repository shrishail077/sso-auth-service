package com.example.sso;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class AuthFlowIntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;

    private String loginBody(String user, String pass) {
        return "{\"username\":\"%s\",\"password\":\"%s\"}".formatted(user, pass);
    }

    private String token(String user, String pass, String field) throws Exception {
        String body = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody(user, pass)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return om.readTree(body).get(field).asText();
    }

    @Test
    void userCanLoginAndCallMe() throws Exception {
        String access = token("user1", "User@123", "accessToken");

        mvc.perform(get("/api/me").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("user1"));
    }

    @Test
    void wrongPasswordReturns401() throws Exception {
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody("user1", "nope")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unknownUserReturns401() throws Exception {
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody("ghost", "whatever")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void missingPasswordReturns400() throws Exception {
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"a\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void noTokenReturns401() throws Exception {
        mvc.perform(get("/api/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void rbacBlocksUserAllowsManagerAndAdmin() throws Exception {
        String user = token("user1", "User@123", "accessToken");
        String manager = token("manager1", "Manager@123", "accessToken");
        String admin = token("admin1", "Admin@123", "accessToken");

        mvc.perform(get("/api/manager/reports").header("Authorization", "Bearer " + user))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/manager/reports").header("Authorization", "Bearer " + manager))
                .andExpect(status().isOk());
        mvc.perform(get("/api/admin/users").header("Authorization", "Bearer " + manager))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/admin/users").header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk());
    }

    @Test
    void logoutRevokesAccessToken() throws Exception {
        String access = token("manager1", "Manager@123", "accessToken");

        mvc.perform(post("/api/auth/logout").header("Authorization", "Bearer " + access))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/me").header("Authorization", "Bearer " + access))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshTokenIsSingleUse() throws Exception {
        String refresh = token("manager1", "Manager@123", "refreshToken");
        String payload = "{\"refreshToken\":\"%s\"}".formatted(refresh);

        mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(payload))
                .andExpect(status().isOk());
        mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(payload))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void accessTokenCannotBeUsedAsRefreshToken() throws Exception {
        String access = token("manager1", "Manager@123", "accessToken");

        mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"%s\"}".formatted(access)))
                .andExpect(status().isUnauthorized());
    }
}
