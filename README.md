# Wazuh SOC Notes

Notas técnicas baseadas em experiências práticas de análise, correlação, Threat Hunting, Incident Response, Detection Engineering e melhoria operacional em ambientes SOC utilizando o Wazuh.

O projeto **Wazuh SOC Notes** tem como objetivo compartilhar estudos de caso, métodos de investigação, queries, correlações, classificações, frameworks e oportunidades de melhoria identificadas durante a análise de eventos e alertas de segurança.

Cada publicação busca ir além da severidade inicial do alerta, reconstruindo o contexto técnico do evento, as evidências disponíveis, o comportamento observado, a cadeia de ataque quando aplicável, o impacto real e o raciocínio utilizado para chegar ao veredito.

Os SOC Notes publicados no LinkedIn apresentam uma visão mais objetiva dos casos.

Neste repositório, os mesmos estudos poderão ser aprofundados com análises técnicas completas, artefatos sanitizados, timelines, Attack Flow, queries, frameworks, métricas, controles defensivos, hardening e oportunidades de melhoria.

---

## 📚 SOC Notes publicados

| Note | Ambiente / Tecnologia | Tema | Classificação | Análise |
|---|---|---|---|---|
| **#001** | Linux / Wazuh | Promiscuous Mode em interfaces `veth` | **Falso Positivo** | [Ver análise completa](notes/001-promiscuous-mode-veth/README.md) |
| **#002** | Cloudflare WAF / Wazuh | Scanning automatizado bloqueado pelo WAF | **Falso Positivo Contextual** | [Ver análise completa](notes/002-cloudflare-waf-scanning/README.md) |
| **#003** | Darktrace / Wazuh | Threat Indicator e Quarantine Device | **Contenção Preventiva** | [Ver análise completa](notes/003-darktrace-quarantine-device/README.md) |
| **#004** | Linux / AF_ALG / Wazuh | CVE-2026-31431 em processo legítimo (`pg_dump`) | **Falso Positivo** | [Ver análise completa](notes/004-cve-2026-31431-af-alg/README.md) |
| **#005** | Windows / Sysmon / Wazuh | Script `.ps1` criado em Windows Temp (`taskhostw.exe`) | **Falso Positivo** | [Ver análise completa](notes/005-sysmon-eid11-filecreate-vs-execution/README.md) |

---

## Objetivos

* Compartilhar conhecimento prático sobre operações de SOC e Resposta a Incidentes.
* Demonstrar métodos de investigação, correlação e Threat Hunting.
* Documentar queries e campos utilizados durante investigações.
* Reconstruir timelines e cadeias de ataque quando houver evidências suficientes.
* Diferenciar evidência, inferência, hipótese e ausência de telemetria.
* Discutir falsos positivos, atividades legítimas, comportamentos suspeitos e incidentes confirmados.
* Identificar lacunas de telemetria, cobertura e capacidade de detecção.
* Relacionar comportamentos observados a frameworks e metodologias aplicáveis.
* Avaliar controles defensivos, hardening e oportunidades de redução da superfície de ataque.
* Explorar Detection Engineering, tuning e melhoria de regras de detecção.
* Aplicar conceitos de governança, maturidade, métricas, SLA e melhoria contínua quando pertinentes.
* Transformar investigações em documentação técnica reutilizável para estudo e desenvolvimento profissional.

Os conteúdos serão adicionados progressivamente, acompanhando as publicações realizadas no LinkedIn e a evolução dos estudos, laboratórios e projetos técnicos.

---

## Estrutura das análises

Sempre que aplicável e sustentado pelas evidências disponíveis, cada SOC Note poderá apresentar:

1. Contexto do alerta.
2. Escopo da investigação.
3. Hipótese inicial.
4. Evidências disponíveis.
5. Timeline dos eventos.
6. Queries de Threat Hunting.
7. Campos e artefatos analisados.
8. Correlação dos eventos.
9. Cadeia de processos e/ou Attack Flow.
10. Mapeamento de TTPs.
11. Classificação do incidente.
12. Veredito técnico.
13. Controles defensivos relacionados.
14. Lacunas de telemetria e detecção.
15. Hardening e recomendações.
16. Métricas operacionais e SLA, quando aplicáveis.
17. Lições aprendidas e melhoria contínua.
18. Referências técnicas e fontes oficiais.

> Nem todos os frameworks, métricas ou metodologias serão aplicáveis a todos os casos.
>
> O mapeamento será realizado conforme o contexto e as evidências disponíveis em cada investigação.

---

# Tecnologias, frameworks e referências

## SIEM e Security Monitoring

* [Wazuh](https://wazuh.com/)

O Wazuh é utilizado como uma das principais plataformas de monitoramento, correlação, análise de eventos, Threat Hunting e suporte às investigações apresentadas neste projeto.

---

## Detection Engineering e telemetria

* [Sigma](https://sigmahq.io/)
* [Sysmon - Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
* [YARA](https://virustotal.github.io/yara/), quando aplicável.

Também poderão ser abordados conceitos relacionados a:

* Detection Engineering.
* Detection-as-Code.
* Baseline de comportamento.
* Tuning de regras.
* Cobertura de detecção.
* Validação de regras.
* Redução de falsos positivos.
* Qualidade e enriquecimento de telemetria.

---

## Threat-Informed Defense e comportamento adversário

* [MITRE ATT&CK](https://attack.mitre.org/)
* [MITRE D3FEND](https://d3fend.mitre.org/)
* [MITRE Engage](https://engage.mitre.org/)
* [MITRE Attack Flow](https://center-for-threat-informed-defense.github.io/attack-flow/)
* [MITRE ATLAS](https://atlas.mitre.org/), quando aplicável a ameaças envolvendo sistemas de Inteligência Artificial.
* [MITRE CAPEC - Common Attack Pattern Enumeration and Classification](https://capec.mitre.org/)
* [Cyber Kill Chain - Lockheed Martin](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
* [Diamond Model of Intrusion Analysis](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)

Esses modelos poderão ser utilizados para analisar diferentes dimensões de uma investigação, como comportamento adversário, TTPs, sequência das ações, relações entre infraestrutura, vítima, capacidade e adversário, além de controles e contramedidas defensivas.

O MITRE Engage será utilizado principalmente quando houver aderência a cenários de adversary engagement, deception, honeypots, honeytokens ou interação controlada com adversários.

---

## Fraude e Social Engineering

* [MITRE Fight Fraud Framework (F3)](https://ctid.mitre.org/fraud#/)
* [VERIS - Vocabulary for Event Recording and Incident Sharing](https://verisframework.org/)
* [MITRE CAPEC](https://capec.mitre.org/)
* [MITRE ATT&CK](https://attack.mitre.org/), quando aplicável.

Casos relacionados a e-mail, fraude e engenharia social poderão considerar classificações como:

* Phishing.
* Spear Phishing.
* Whaling.
* BEC - Business Email Compromise.
* Vishing.
* Smishing.
* Quishing.
* Callback Phishing / TOAD.
* Credential Harvesting.
* Malware Delivery.
* Malicious Link.
* Spam.
* Impersonation.
* Spoofing.
* Display Name Spoofing.
* Look-alike Domain.
* Homograph / IDN Homograph.
* Typosquatting.
* Clone Phishing.
* Thread Hijacking.
* Campanhas internas controladas e autorizadas de conscientização.
* Marketing legítimo.

O objetivo é diferenciar corretamente ameaça, fraude, abuso, comunicação indesejada, atividade legítima e campanhas controladas.

---

## Segurança e autenticação de e-mail

Quando aplicável, poderão ser analisados mecanismos de autenticação, transporte, alinhamento e cadeia de confiança de mensagens.

* [SPF - RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208)
* [DKIM - RFC 6376](https://datatracker.ietf.org/doc/html/rfc6376)
* [DMARC - RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489)
* [ARC - RFC 8617](https://datatracker.ietf.org/doc/html/rfc8617)
* [Authentication-Results - RFC 8601](https://datatracker.ietf.org/doc/html/rfc8601)
* [SMTP - RFC 5321](https://datatracker.ietf.org/doc/html/rfc5321)
* [Internet Message Format - RFC 5322](https://datatracker.ietf.org/doc/html/rfc5322)
* [List-Unsubscribe - RFC 2369](https://datatracker.ietf.org/doc/html/rfc2369)
* [One-Click Unsubscribe - RFC 8058](https://datatracker.ietf.org/doc/html/rfc8058)

Esses mecanismos serão considerados como evidências dentro do contexto completo da mensagem e não como prova isolada de legitimidade ou maliciosidade.

---

## Incident Response e Cybersecurity

* [NIST Cybersecurity Framework (CSF)](https://www.nist.gov/cyberframework)
* [NIST SP 800-61 Rev. 3 - Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
* [NIST SP 800-86 - Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)
* [CISA](https://www.cisa.gov/)
* [FIRST](https://www.first.org/)
* [FIRST CSIRT Services Framework](https://www.first.org/standards/frameworks/csirts/)
* [VERIS](https://verisframework.org/)
* [ISO/IEC 27035 - Information Security Incident Management](https://www.iso.org/standard/78973.html)

Essas referências poderão ser utilizadas para estruturar investigação, classificação, resposta, contenção, recuperação, documentação e melhoria pós-incidente.

---

## Threat Intelligence

* [STIX - Structured Threat Information Expression](https://oasis-open.github.io/cti-documentation/stix/intro.html)
* [TAXII - Trusted Automated Exchange of Intelligence Information](https://oasis-open.github.io/cti-documentation/taxii/intro.html)
* [MISP](https://www.misp-project.org/)
* [FIRST Traffic Light Protocol - TLP](https://www.first.org/tlp/)
* [Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
* [Diamond Model of Intrusion Analysis](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)

Também poderão ser utilizados conceitos relacionados a:

* IOC - Indicator of Compromise.
* IOA - Indicator of Attack.
* Enriquecimento de indicadores.
* Reputação.
* Infraestrutura adversária.
* Contextualização de ameaças.
* Compartilhamento de inteligência.

---

## Vulnerabilidades e priorização de risco

* [CVE Program](https://www.cve.org/)
* [NIST National Vulnerability Database - NVD](https://nvd.nist.gov/)
* [MITRE CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
* [CVSS - Common Vulnerability Scoring System](https://www.first.org/cvss/)
* [EPSS - Exploit Prediction Scoring System](https://www.first.org/epss/)
* [CISA Known Exploited Vulnerabilities - KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

Quando aplicável, a análise poderá correlacionar:

**CVE → CWE → CVSS → EPSS → KEV → contexto ambiental → evidências de exploração**

A severidade técnica de uma vulnerabilidade não será utilizada isoladamente como representação do risco real.

---

## Hardening e Secure Configuration

* [CIS Controls](https://www.cisecurity.org/controls)
* [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
* [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
* [DISA STIGs](https://public.cyber.mil/stigs/)
* [NIST SP 800-53 - Security and Privacy Controls](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
* [NIST SP 800-123 - Guide to General Server Security](https://csrc.nist.gov/pubs/sp/800/123/final)
* [NIST SP 800-190 - Application Container Security Guide](https://csrc.nist.gov/pubs/sp/800/190/final)
* [CISA Secure by Design](https://www.cisa.gov/securebydesign)
* [OWASP ASVS - Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
* [CSA Cloud Controls Matrix - CCM](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
* [IEC 62443](https://www.iec.ch/cyber-security), quando aplicável a ambientes OT/ICS.

As recomendações de hardening poderão considerar redução da superfície de ataque, configuração segura, controle de privilégios, serviços desnecessários, logging, autenticação, segmentação, políticas de execução, configurações de endpoint, cloud e demais controles aplicáveis.

---

## Governança, risco e controles

* [ISO/IEC 27001 - Information Security Management Systems](https://www.iso.org/standard/27001)
* [ISO/IEC 27002 - Information Security Controls](https://www.iso.org/standard/75652.html)
* [ISO/IEC 27005 - Information Security Risk Management](https://www.iso.org/standard/80585.html)
* [ISO/IEC 27701 - Privacy Information Management](https://www.iso.org/standard/85819.html)
* [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
* [CIS Controls](https://www.cisecurity.org/controls)
* [COBIT - ISACA](https://www.isaca.org/resources/cobit)
* [FAIR - Factor Analysis of Information Risk](https://www.fairinstitute.org/)

Essas referências poderão ser utilizadas para relacionar descobertas técnicas a controles, riscos, governança, responsabilidade e melhoria organizacional.

---

## Continuidade e resiliência

* [ISO 22301 - Business Continuity Management Systems](https://www.iso.org/standard/75106.html)
* [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

Princípios de Business Continuity, Disaster Recovery e Cyber Resilience poderão ser considerados quando o impacto ou a resposta ao incidente possuir relação com disponibilidade, recuperação ou continuidade operacional.

---

## Zero Trust e Identity Security

* [NIST SP 800-207 - Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)

Também poderão ser considerados conceitos relacionados a:

* Least Privilege.
* MFA - Multi-Factor Authentication.
* RBAC - Role-Based Access Control.
* ABAC - Attribute-Based Access Control.
* Identity Security.
* Privileged Access.
* Segmentação.
* Autenticação contínua.
* Redução de confiança implícita.

---

## Application Security, Cloud e DevSecOps

* [OWASP Top 10](https://owasp.org/www-project-top-ten/)
* [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
* [OWASP SAMM](https://owaspsamm.org/)
* [CSA Cloud Controls Matrix - CCM](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
* [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
* [CISA Cybersecurity Performance Goals - CPGs](https://www.cisa.gov/cybersecurity-performance-goals)

Essas referências poderão ser utilizadas quando as investigações envolverem aplicações, APIs, workloads em cloud, containers, pipelines, configurações inseguras ou componentes relacionados a DevSecOps.

---

## SOC Maturity

* [SOC-CMM](https://www.soc-cmm.com/)
* [FIRST CSIRT Services Framework](https://www.first.org/standards/frameworks/csirts/)
* [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

Conceitos de maturidade poderão ser utilizados para avaliar capacidades relacionadas a:

* Pessoas.
* Processos.
* Tecnologia.
* Detecção.
* Resposta.
* Threat Intelligence.
* Métricas.
* Governança.
* Melhoria contínua.

---

## Service Management e melhoria contínua

* [ITIL - PeopleCert](https://www.peoplecert.org/ITIL-4)
* [Agile Manifesto](https://agilemanifesto.org/)
* [Scrum Guide](https://scrumguides.org/)
* [Kanban Guides](https://kanbanguides.org/)

Também poderão ser utilizados conceitos de:

* Incident Management.
* Problem Management.
* Monitoring and Event Management.
* Service Level Management.
* Change Enablement.
* Continual Improvement.
* Agile.
* Scrum.
* Kanban.
* PDCA.
* Gestão de backlog.
* Priorização de melhorias.

Essas referências poderão apoiar a relação entre investigação técnica, operação do SOC, mudanças, SLA e evolução contínua dos processos de segurança.

---

## Métricas operacionais

Quando houver dados disponíveis e contexto adequado, os estudos poderão considerar:

* KPI - Key Performance Indicator.
* KRI - Key Risk Indicator.
* SLA - Service Level Agreement.
* SLO - Service Level Objective.
* MTTD - Mean Time to Detect.
* MTTA - Mean Time to Acknowledge.
* MTTC - Mean Time to Contain.
* MTTR - com definição explícita do significado utilizado no contexto.
* Dwell Time.
* False Positive Rate.
* Detection Coverage.
* Escalation Rate.

As métricas serão utilizadas somente quando houver dados suficientes para calculá-las ou analisá-las de forma responsável.

O objetivo não será apenas medir velocidade, mas compreender eficiência operacional, capacidade de detecção, qualidade da resposta e oportunidades de melhoria.

---

## Classificação das evidências

Para evitar que ausência de informação seja interpretada como evidência, as análises poderão diferenciar:

* **Confirmed** - sustentado diretamente pelas evidências.
* **Supported** - sustentado por múltiplos indícios.
* **Inferred** - conclusão analítica baseada nas evidências disponíveis.
* **Hypothesis** - hipótese que ainda necessita validação.
* **Not Observed** - investigado, mas não observado.
* **Not Available** - a telemetria disponível não permite determinar.
* **Not Applicable** - não aplicável ao cenário.

Essa classificação busca preservar a diferença entre fato observado, interpretação analítica e ausência de visibilidade.

---

## Princípio de utilização dos frameworks

Este projeto não busca aplicar todos os frameworks, metodologias, padrões ou métricas a todos os casos.

Cada referência será utilizada somente quando houver aderência técnica ao cenário analisado.

O objetivo é utilizar diferentes modelos como perspectivas complementares para compreender:

**o que aconteceu → como aconteceu → em qual sequência → quais evidências sustentam a análise → quais controles existiam → quais lacunas foram identificadas → qual foi o impacto → como responder → como melhorar**

Um mesmo incidente poderá, por exemplo, ser analisado sob diferentes perspectivas:

* MITRE ATT&CK para comportamento adversário.
* Attack Flow para reconstrução da sequência de ações.
* D3FEND para contramedidas defensivas.
* Fight Fraud Framework para fraude.
* VERIS para classificação estruturada.
* NIST para Incident Response.
* CVSS, EPSS e KEV para vulnerabilidades.
* CIS e Security Baselines para hardening.
* ISO e COBIT para governança.
* SOC-CMM para maturidade.
* ITIL para gestão operacional.
* KPI e métricas de tempo para desempenho do SOC.

A utilização de múltiplas referências não significa que todas serão aplicáveis simultaneamente.

---

## Aviso sobre os dados

Os casos compartilhados neste repositório são sanitizados para preservar a confidencialidade dos ambientes analisados.

Nomes de organizações, clientes, usuários, endereços de e-mail, endereços IP, domínios, hostnames, identificadores de incidentes, credenciais e demais informações sensíveis são removidos, substituídos ou generalizados antes da publicação.

Quando necessário, valores fictícios ou placeholders poderão ser utilizados exclusivamente para preservar o contexto técnico da análise.

Os conteúdos representam estudos técnicos e não expõem intencionalmente informações confidenciais de organizações ou usuários.

Campanhas internas controladas, exercícios de conscientização e demais atividades autorizadas serão igualmente sanitizados.

O objetivo deste projeto é compartilhar **metodologia, raciocínio analítico, técnicas de investigação e aprendizado**, e não informações pertencentes aos ambientes onde os eventos foram originalmente observados.

---

## Autor

**Felipe Amaral**

Profissional de Cibersegurança com atuação em Security Operations Center, Incident Response, Threat Hunting e melhoria contínua de detecções.

* GitHub: [Fe-Amaral](https://github.com/Fe-Amaral)
* LinkedIn: [Felipe Amaral](https://www.linkedin.com/in/felipe-r-amaral/)

---

Este é um projeto independente de compartilhamento de conhecimento e não representa documentação oficial do Wazuh, MITRE, NIST, FIRST, CISA, ISO ou das demais organizações, tecnologias, padrões e frameworks mencionados.
