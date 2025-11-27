package com.posgrado.intranet.common.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

@Component
@ConfigurationProperties(prefix = "spring.mail")
@Data
public class MailProperties {
  private String username;
}
