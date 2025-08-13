**Overview**

Atualizar bibliotecas apontadas pelo SCA reduz imediatamente a superfície de ataque e evita que uma única dependência comprometida degrade todo o sistema. Na prática, a correção costuma ser simples:  atualizar para a versão corrigida.
No Exemplo abaixo tem-se o logback: 

logback-core de 1.2.13 (vulnerável) → 1.5.14 (sem vulnerabilidade reportada).


Vulnerável: https://mvnrepository.com/artifact/ch.qos.logback/logback-core/1.2.13

Recomendada: https://mvnrepository.com/artifact/ch.qos.logback/logback-core/1.5.14

1) **gson-2.9.0.jar**
**Regra/ID:** CVE-2025-53864 (gson)  
**Local:** `gson-2.9.0.jar` — `pkg:maven/com.google.code.gson/gson@2.9.0`  
**Descrição:** Overflow de buffer na pilha associado ao uso de `gson` (relato OSS Index / sigstore-java). Pode levar a corrupção de memória/DoS durante o parsing de dados.  
**Severidade:** **Média** — CVSS base 6.9 (vetor CVSS 4.0).  
**Cenário de exploração:** Parsing de JSON não confiável em serviços que dependem de `gson` 2.9.0 pode disparar a condição de overflow em caminhos específicos de uso de bibliotecas que o integram (ex.: wrappers ou plugins que repassam dados sem validação), causando crash do processo.  
**Mitigações recomendadas:** Atualizar `gson` para versão sem a exposição (≥ 2.10.x); aplicar validação/limitação de tamanho de payloads JSON, além de habilitar monitoração.

2) **h2-2.3.232.jar**
**Regra/ID:** CVE-2018-14335 (H2 Database)  
**Local:** `h2-2.3.232.jar` — `pkg:maven/com.h2database/h2@2.3.232`  
**Descrição:** -  resolução indevida de links simbólicos possibilitando acesso a recurso não intencional.  
**Severidade:** **Média** — CVSS v3 base 6.0.  
**Cenário de exploração:** Em ambientes onde o H2 acessa arquivos por nomes (caminhos de base de dados/exports) um invasor com capacidade de criar symlinks pode redirecionar o acesso a local sensível, expondo confidencialidade.  
**Mitigações recomendadas:** Atualizar H2 para versão corrigida; isolar diretórios de trabalho do H2 com permissões rígidas; desabilitar resoluções de caminho não necessárias; validar e normalizar caminhos antes de uso.


3) **h2-2.3.232.jar**
**Regra/ID:** CVE-2024-12798 (Logback Core)  
**Local:** `logback-core-1.2.13.jar` — `pkg:maven/ch.qos.logback/logback-core@1.2.13`  
**Descrição:** Execução arbitrária de código via `JaninoEventEvaluator` quando um atacante consegue comprometer/fornecer arquivo de configuração XML do Logback. Requer privilégio prévio (escrita em config ou injeção de variável de ambiente).  
**Severidade:** **Média** — CVSS base 5.9.  
**Cenário de exploração:** Um operador mal-intencionado com acesso a `logback.xml` (ou apontando a config via variável de ambiente) habilita expressões maliciosas e executa código no contexto da aplicação.  
**Mitigações recomendadas:** Atualizar para versão do Logback sem a exposição; proteger rigorosamente os arquivos de configuração (permissões de leitura-apenas, integridade); desabilitar extensões dinâmicas (Janino) quando não estritamente necessárias;
