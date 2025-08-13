1) **Content Security Policy (CSP) Header Not Set**
**Regra/ID:** ZAP 10038
**Local:** `http://localhost:9090/`, `/robots.txt`, `/sitemap.xml`, `/VulnerableApp/`  
**Descrição:** Ausência do cabeçalho Content-Security-Policy, que limita as origens de scripts/estilos/imagens e mitiga XSS e injeções no navegador.  
**Severidade**: **Médio (ZAP)** — trate como Alto em produção, pois amplia qualquer XSS.  
**Cenário de exploração**: Um input refletido injeta `<script>` ou carrega JS remoto, permitindo roubo de sessão, keylogging ou exfiltração.  
**Mitigações recomendadas**: Definir CSP restritivo (ex.: `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`), usar nonce/hash para inline scripts e validar em `Report-Only` antes do enforcement.

2) **Missing Anti-clickjacking Header**
**Regra/ID:** ZAP 10020
**Local:** `http://localhost:9090/VulnerableApp/`  
**Descrição:** Resposta sem `X-Frame-Options` ou `Content-Security-Policy: frame-ancestors`, deixando a página vulnerável a clickjacking.  
**Severidade**: **Médio (ZAP)** — impacto Alto se houver ações sensíveis na UI.  
**Cenário de exploração**: Atacante embute a página em um iframe invisível e induz cliques do usuário em botões críticos (transferência, troca de e-mail).  
**Mitigações recomendadas**: Preferir `Content-Security-Policy: frame-ancestors 'none'` (ou `SAMEORIGIN` quando necessário). Alternativamente, usar `X-Frame-Options: DENY|SAMEORIGIN`.

3) **X-Content-Type-Options Header Missing**
**Regra/ID:** ZAP 10021
**Local:** `http://localhost:9090/VulnerableApp/`  
**Descrição:** Ausência de `X-Content-Type-Options: nosniff` permite _MIME sniffing_ em navegadores antigos, podendo interpretar conteúdo como tipo indevido.  
**Severidade**: **Baixo (ZAP)** — Médio em ambientes com conteúdo misto/downloads.  
**Cenário de exploração**: Um arquivo ou resposta de erro é _sniffado_ como `text/html`, possibilitando execução de HTML/JS não intencional.  
**Mitigações recomendadas**: Definir `X-Content-Type-Options: nosniff` e revisar Content-Type corretos em respostas estáticas/dinâmicas (incluindo páginas de erro).