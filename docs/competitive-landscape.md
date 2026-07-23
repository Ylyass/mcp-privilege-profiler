# Competitive landscape and project positioning

Reviewed on 2026-07-23. This is engineering positioning, not a trademark,
package-name, or legal clearance.

## What already exists

| Project or platform | Verified overlapping capabilities | How this project should relate |
|---|---|---|
| MCP standard | Open protocol plus security guidance for authorization, local-server compromise, confused-deputy risks, SSRF, consent, and token handling | Implement the protocol and its guidance; do not present MCP itself as this project's invention |
| Anthropic products | Connector controls, including user and organization choices and one-time or persistent access | Treat Anthropic as a product platform and MCP originator, not as a missing security layer |
| OpenAI Agents SDK | stdio and HTTP MCP clients, static and dynamic tool filtering, per-tool approvals, tracing, and agent orchestration | This proxy can be evaluated as a vendor-neutral downstream control; it does not replace the agent SDK |
| Docker MCP Gateway and Toolkit | Server lifecycle, container isolation, catalogs, credentials, profiles, access control, logging, and call tracing | Docker is stronger for packaging and operating server fleets; this project focuses on evidence-to-policy and Wazuh evidence |
| Microsoft Foundry AI Gateway | Authentication, rate limits, IP restrictions, centralized observability, and audit for governed MCP tools; documented as preview | Microsoft is stronger for Azure enterprise governance; this project is a local, inspectable Wazuh-oriented reference |
| Microsoft Agent Governance Toolkit | Broad policy, identity, audit, sandboxing, drift, and MCP gateway capabilities | Treat it as direct open-source overlap; differentiate only with tested workflow details, not broad superiority claims |

Primary sources:

- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [Anthropic's agent trust and connector controls](https://www.anthropic.com/news/our-framework-for-developing-safe-and-trustworthy-agents)
- [OpenAI Agents SDK MCP integration](https://openai.github.io/openai-agents-python/mcp/)
- [Docker MCP Gateway](https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/)
- [Microsoft Foundry MCP tool governance](https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/tools/governance?view=foundry)
- [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)

## Defensible project focus

MCP Privilege Profiler is not a replacement for those platforms. Its current
focus is a small, auditable workflow:

1. observe labeled successful use without storing raw arguments or results;
2. produce candidate evidence rather than silently granting permissions;
3. require an explicit human review;
4. enforce an exact, deny-by-default task policy;
5. bind decisions to complete tool-definition fingerprints and fail closed on
   drift;
6. enforce reviewed path, host, enum, byte, rate, task, concurrency, and
   single-use approval constraints;
7. write privacy-minimized mandatory events before forwarding; and
8. ship a tested Wazuh decoder, rules, fixtures, live probe, and reproducible
   benchmark evidence.

The honest claim is not "nobody else does MCP security." The claim is:

> This repository is an inspectable reference implementation of a
> human-reviewed, evidence-to-least-privilege workflow for one local stdio MCP
> server, with exact drift enforcement and a Wazuh-native detection bridge.

## Who may use it

Good early users:

- security engineers evaluating MCP least-privilege controls;
- Wazuh users who want reproducible MCP-specific detection fixtures;
- researchers and students who need an inspectable local reference;
- small engineering teams willing to review policies and operate within the
  documented single-server stdio boundary; and
- maintainers comparing policy, drift, audit, and approval designs.

Not a current fit:

- organizations requiring a supported production service or warranty;
- remote multi-tenant OAuth deployments;
- large multi-server routing and lifecycle management;
- identity federation, enterprise administration, or cloud control planes;
- automatic protection from every prompt injection; or
- teams that cannot perform the required human policy review.

## Publication rule

Public descriptions must lead with measured behavior and limitations. Avoid
"first," "unique," "complete," "enterprise-ready," and "prevents prompt
injection" unless independently proven for a precisely defined claim.
