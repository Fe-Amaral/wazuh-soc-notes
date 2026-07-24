# Wazuh SOC Notes

Notas técnicas baseadas em experiências práticas de análise, correlação, hunting e melhoria operacional em ambientes SOC utilizando o Wazuh.

O projeto **Wazuh SOC Notes** tem como objetivo compartilhar estudos de casos, métodos de investigação, consultas e oportunidades de melhoria identificadas durante a triagem de alertas de segurança.

Cada publicação apresenta o raciocínio técnico aplicado ao evento, indo além da severidade inicial do alerta para avaliar contexto, comportamento, evidências disponíveis e impacto real.

## Objetivos

* Compartilhar conhecimento prático sobre operações de SOC.
* Demonstrar métodos de investigação e correlação de alertas.
* Documentar consultas utilizadas em atividades de hunting.
* Discutir falsos positivos e lacunas de telemetria.
* Propor melhorias de regras, campos e processos de detecção.
* Relacionar os casos ao MITRE ATT&CK quando houver aderência técnica.

Os conteúdos serão adicionados progressivamente, acompanhando as publicações realizadas no LinkedIn.

## Estrutura das análises

Sempre que aplicável, cada SOC Note poderá apresentar:

1. Contexto do alerta.
2. Hipótese inicial.
3. Evidências disponíveis.
4. Queries de hunting.
5. Correlação dos eventos.
6. Veredito técnico.
7. Lacunas identificadas.
8. Recomendações de melhoria.
9. Referências técnicas.

## Tecnologias e referências

* [Wazuh](https://wazuh.com/)
* [MITRE ATT&CK](https://attack.mitre.org/)
* [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
* [Sysmon – Microsoft Sysinternals](https://learn.microsoft.com/sysinternals/downloads/sysmon)

## Aviso sobre os dados

Os casos compartilhados neste repositório são sanitizados para preservar a confidencialidade dos ambientes analisados.

Nomes de clientes, usuários, endereços de e-mail, endereços IP, domínios, hostnames, identificadores de incidentes e demais informações sensíveis são removidos, substituídos ou generalizados antes da publicação.

Os conteúdos representam estudos técnicos e não expõem intencionalmente informações confidenciais de organizações ou usuários.

## Autor

**Fernando Amaral**

Profissional de Cibersegurança com atuação em Security Operations Center, análise de incidentes, hunting e melhoria contínua de detecções.

* GitHub: [Fe-Amaral](https://github.com/Fe-Amaral)
* LinkedIn: https://www.linkedin.com/in/felipe-r-amaral/

---

Este é um projeto independente de compartilhamento de conhecimento e não representa documentação oficial do Wazuh.
