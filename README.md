# Wazuh SOC Notes

Notas técnicas baseadas em experiências práticas de análise, correlação, Threat Hunting, Incident Response, Detection Engineering e melhoria operacional em ambientes SOC utilizando o Wazuh.

O projeto **Wazuh SOC Notes** tem como objetivo compartilhar estudos de caso, métodos de investigação, queries, correlações, classificações, frameworks e oportunidades de melhoria identificadas durante a análise de eventos e alertas de segurança.

Cada publicação busca ir além da severidade inicial do alerta, reconstruindo o contexto técnico do evento, as evidências disponíveis, o comportamento observado, a cadeia de ataque quando aplicável, o impacto real e o raciocínio utilizado para chegar ao veredito.

Os SOC Notes publicados no LinkedIn apresentam uma visão mais objetiva dos casos.

Neste repositório, os mesmos estudos poderão ser aprofundados com análises técnicas completas, artefatos sanitizados, timelines, Attack Flow, queries, frameworks, métricas, controles defensivos, hardening e oportunidades de melhoria.

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
* Explorar Detection Engineering e melhoria de regras de detecção.
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
> O mapeamento será realizado conforme o contexto e as evidências disponíveis em cada investigação.

---

# Tecnologias, frameworks e referências

## SIEM e Security Monitoring

* [Wazuh](https://wazuh.com/)

## Detection Engineering e telemetria

* [Sigma](https://sigmahq.io/)
* [Sysmon - Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
* YARA, quando aplicável.
* Detection Engineering e Detection-as-Code.
* Baseline, tuning e validação de regras.

## Threat-Informed Defense e comportamento adversário

* [MITRE ATT&CK](https://attack.mitre.org/)
* [MITRE D3FEND](https://d3fend.mitre.org/)
* [MITRE Engage](https://engage.mitre.org/)
* MITRE Attack Flow.
* Cyber Kill Chain.
* Diamond Model of Intrusion Analysis.
* CAPEC - Common Attack Pattern Enumeration and Classification.
* MITRE ATLAS, quando aplicável a ameaças envolvendo sistemas de IA.

O MITRE Engage será utilizado principalmente quando houver aderência a cenários de adversary engagement, deception ou interação controlada com adversários.

## Fraude e Social Engineering

* [MITRE Fight Fraud Framework (F3)](https://ctid.mitre.org/fraud#/)
* VERIS - Vocabulary for Event Recording and Incident Sharing.
* CAPEC.
* MITRE ATT&CK, quando aplicável.

Casos relacionados a e-mail e engenharia social poderão considerar classificações como:

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

Também poderão ser avaliados SPF, DKIM, DMARC, ARC e demais padrões e RFCs relacionados à autenticação e transporte de e-mail.

## Incident Response e Cybersecurity

* [NIST Cybersecurity Framework (CSF)](https://www.nist.gov/cyberframework)
* [NIST SP 800-61 - Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
* [NIST SP 800-86 - Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)
* [CISA](https://www.cisa.gov/)
* [FIRST](https://www.first.org/)
* FIRST CSIRT Services Framework.
* VERIS.
* ISO/IEC 27035.

## Threat Intelligence

* STIX.
* TAXII.
* MISP.
* FIRST Traffic Light Protocol (TLP).
* Pyramid of Pain.
* Diamond Model.
* IOC e IOA.

## Vulnerabilidades e priorização de risco

* [CVE Program](https://www.cve.org/)
* [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* CWE - Common Weakness Enumeration.
* [CVSS - Common Vulnerability Scoring System](https://www.first.org/cvss/)
* EPSS - Exploit Prediction Scoring System.
* [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

Quando aplicável, a análise poderá correlacionar:

CVE → CWE → CVSS → EPSS → KEV → contexto ambiental → evidências de exploração.

## Hardening e Secure Configuration

* CIS Controls.
* CIS Benchmarks.
* Microsoft Security Baselines.
* DISA STIGs.
* NIST SP 800-53.
* NIST SP 800-123.
* NIST SP 800-190, quando aplicável a containers.
* CISA Secure by Design / Secure by Default.
* OWASP ASVS.
* CSA Cloud Controls Matrix.
* IEC 62443, quando aplicável a ambientes OT/ICS.

## Governança, risco e controles

* ISO/IEC 27001.
* ISO/IEC 27002.
* ISO/IEC 27005.
* ISO/IEC 27701.
* NIST Cybersecurity Framework.
* CIS Controls.
* COBIT.
* FAIR.
* NIST SP 800-53.

## Continuidade e resiliência

* ISO 22301.
* NIST Cybersecurity Framework - Recover.
* Princípios de Business Continuity e Disaster Recovery, quando aplicáveis.

## Zero Trust e Identity Security

* NIST SP 800-207 - Zero Trust Architecture.
* Least Privilege.
* MFA.
* RBAC.
* ABAC.
* Princípios de identidade e controle de acesso aplicáveis ao cenário investigado.

## Application Security, Cloud e DevSecOps

* OWASP Top 10.
* OWASP ASVS.
* OWASP SAMM.
* CSA Cloud Controls Matrix.
* CIS Benchmarks.
* CISA Cybersecurity Performance Goals, quando aplicáveis.

## SOC Maturity

* [SOC-CMM](https://www.soc-cmm.com/)
* FIRST CSIRT Services Framework.
* NIST Cybersecurity Framework.
* Conceitos de capacidade, maturidade e melhoria contínua de operações de segurança.

## Service Management e melhoria contínua

* ITIL.
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

Essas referências poderão ser utilizadas para relacionar investigações técnicas à gestão operacional, backlog de melhorias, mudanças, qualidade do serviço e evolução contínua do SOC.

## Métricas operacionais

Quando houver dados disponíveis e contexto adequado, os estudos poderão considerar:

* KPI - Key Performance Indicator.
* KRI - Key Risk Indicator.
* SLA - Service Level Agreement.
* SLO - Service Level Objective.
* MTTD - Mean Time to Detect.
* MTTA - Mean Time to Acknowledge.
* MTTC - Mean Time to Contain.
* MTTR - com definição explícita da métrica utilizada no contexto.
* Dwell Time.
* False Positive Rate.
* Detection Coverage.
* Escalation Rate.

As métricas serão utilizadas apenas quando houver evidências suficientes para calculá-las ou analisá-las de forma responsável.

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

---

## Princípio de utilização dos frameworks

Este projeto não busca aplicar todos os frameworks a todos os casos.

Cada framework, metodologia, padrão ou métrica será utilizado somente quando houver aderência técnica ao cenário analisado.

O objetivo é utilizar diferentes modelos como perspectivas complementares para compreender:

**o que aconteceu → como aconteceu → em qual sequência → quais evidências sustentam a análise → quais controles existiam → quais lacunas foram identificadas → qual foi o impacto → como responder → como melhorar.**

---

## Aviso sobre os dados

Os casos compartilhados neste repositório são sanitizados para preservar a confidencialidade dos ambientes analisados.

Nomes de organizações, clientes, usuários, endereços de e-mail, endereços IP, domínios, hostnames, identificadores de incidentes, credenciais e demais informações sensíveis são removidos, substituídos ou generalizados antes da publicação.

Quando necessário, valores fictícios ou placeholders poderão ser utilizados exclusivamente para preservar o contexto técnico da análise.

Os conteúdos representam estudos técnicos e não expõem intencionalmente informações confidenciais de organizações ou usuários.

Campanhas internas controladas, exercícios de conscientização e demais atividades autorizadas serão igualmente sanitizados.

---

## Autor

**Felipe Amaral**

Profissional de Cibersegurança com atuação em Security Operations Center, Incident Response, Threat Hunting e melhoria contínua de detecções.

* GitHub: [Fe-Amaral](https://github.com/Fe-Amaral)
* LinkedIn: <https://www.linkedin.com/in/felipe-r-amaral/>

---

Este é um projeto independente de compartilhamento de conhecimento e não representa documentação oficial do Wazuh, MITRE, NIST, FIRST, CISA ou das demais organizações e frameworks mencionados.
