package ru.aurorahost.server.constant;

public class SecurityConstant {
    public static final long EXPIRATION_TIME = 1000 * 60 * 60 * 24 * 5; // 5 days
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String JWT_TOKEN_HEADER = "Jwt-Token";
    public static final String TOKEN_CANNOT_BE_VERIFIED = "Token cannot be verified";
    public static final String AURORA_HOST_SUPPORT_PORTAL = "Aurora Host Support Portal";
    public static final String AURORA_HOST_SUPPORT_PORTAL_ADMINISTRATION = "Aurora Host Support Portal Administration";
    public static final String AUTHORITIES = "authorities";
    public static final String FORBIDDEN_MESSAGE = "You need to lon in to access this page";
    public static final String ACCESS_DENIED_MESSAGE = "You do not have permission to access this page";
    public static final String OPTIONS_HTTP_METHOD = "OPTIONS";
    public static final String[] PUBLIC_URL = {"/user/login", "/user/register", "/user/resetpassword/**", "/user/image/**"};
}
