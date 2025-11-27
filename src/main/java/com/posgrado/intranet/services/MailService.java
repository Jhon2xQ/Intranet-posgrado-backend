package com.posgrado.intranet.services;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;

import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StreamUtils;

import com.posgrado.intranet.common.config.CustomUserDetails;
import com.posgrado.intranet.common.config.CustomUserDetailsService;
import com.posgrado.intranet.common.properties.MailProperties;
import com.posgrado.intranet.common.utils.JwtUtil;
import com.posgrado.intranet.entities.TbResidentadoPasswordReset;
import com.posgrado.intranet.repositories.ResidentadoPasswordResetRepository;

import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class MailService {

  private final JavaMailSender mailSender;
  private final MailProperties mailProperties;
  private final JwtUtil jwtUtil;
  private final CustomUserDetailsService userDetailsService;
  private final ResidentadoPasswordResetRepository passwordResetRepository;

  @Transactional
  public void sendForgotPassMail(String username) {

    CustomUserDetails userDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(username);
    if (!userDetails.isEnabled()) {
      throw new RuntimeException("El usuario esta inhabilitado");
    }

    String token = jwtUtil.generatePassResetToken(username);
    sendMessage(username, token);
    TbResidentadoPasswordReset passwordReset = new TbResidentadoPasswordReset();
    passwordReset.setToken(token);
    passwordReset.setUsuario(username);
    passwordReset.setExpiracion(LocalDateTime.now().plusHours(1));
    passwordResetRepository.save(passwordReset);
  }

  private void sendMessage(String username, String token) {
    try {
      MimeMessage message = mailSender.createMimeMessage();
      MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
      helper.setTo(username + "@unsaac.edu.pe");
      helper.setSubject("Cambio de Contraseña: EPG-UNSAAC");
      helper.setText(generateContent(token), true);
      helper.setFrom(mailProperties.getUsername());
      mailSender.send(message);
    } catch (Exception e) {
      throw new RuntimeException("Error al generar", e);
    }
  }

  private String generateContent(String token) {
    try {
      String resetLink = "https://alumnos-epg.unsaac.edu.pe/update-forgot-password?token=" + token;
      ClassPathResource resource = new ClassPathResource("templates/reset-password.html");
      String htmlTemplate = StreamUtils.copyToString(
          resource.getInputStream(),
          StandardCharsets.UTF_8);
      String htmlContent = htmlTemplate.replace("{{RESET_LINK}}", resetLink);
      return htmlContent;

    } catch (Exception e) {
      throw new RuntimeException("Error al cargar el template de email", e);
    }
  }
}
