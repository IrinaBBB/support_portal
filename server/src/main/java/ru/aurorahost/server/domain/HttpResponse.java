package ru.aurorahost.server.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;


@Data
@Builder
@AllArgsConstructor
public class HttpResponse {
    private int httpStatusCode;
    private HttpStatus httpStatus;
    private String reason;
    private String message;
}
