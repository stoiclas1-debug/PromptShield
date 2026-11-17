# PromptShield

## Security testing for the AI instruction layer

PromptShield is an open-source security project for finding weaknesses in prompts, AI agents, and tool-enabled workflows before attackers—or unexpected content—can exploit them.

Modern AI systems do more than answer questions. They read documents, browse the web, call tools, handle sensitive context, and make decisions across application boundaries. PromptShield is designed to help teams test those instruction paths, expose unsafe assumptions, and build stronger controls around AI behavior.

> **Status:** PromptShield is in early development. The repository is currently a foundation for the project; implementation work is being built out and no production security guarantees are claimed.

## What PromptShield is meant to protect

PromptShield focuses on the places where trusted instructions meet untrusted content:

- System, developer, and user instruction boundaries
- Retrieved documents and web content
- Tool calls and agent action selection
- Secrets, private data, and internal context
- Jailbreak and prompt-injection resistance
- Security regressions introduced during prompt or workflow changes

## Core capabilities

The project is being shaped around a practical security workflow:

### Discover
Model the AI workflow, identify trust boundaries, and map the data and tools that can influence behavior.

### Attack
Run structured prompt-injection, jailbreak, instruction-confusion, and data-exposure scenarios against the workflow.

### Evaluate
Capture what happened, compare results across versions, and identify unsafe or unexpected behavior.

### Harden
Turn findings into concrete improvements: stronger instruction separation, narrower tool permissions, safer context handling, validation, and human approval where appropriate.

### Repeat
Keep security tests versioned and repeatable so prompt and agent changes do not silently reintroduce known weaknesses.

## Design principles

- **Untrusted by default:** User input, retrieved content, web pages, and tool output should not gain authority merely because an AI model can read them.
- **Least privilege:** Agents should receive only the tools, data, and permissions required for the task.
- **Defense in depth:** Prompts are one control layer—not a replacement for application authorization, input validation, isolation, monitoring, or human review.
- **Evidence over confidence:** Security claims should be tied to reproducible tests, observed behavior, and clearly stated limitations.
- **Developer-friendly security:** Findings should be understandable, actionable, and easy to integrate into normal engineering workflows.

## Intended users

PromptShield is for:

- Developers building AI-enabled applications
- Application-security and product-security teams
- AI platform and agent-framework engineers
- Red-teamers and security researchers
- Organizations that need a repeatable way to review AI workflows before deployment

## Early roadmap

- [ ] Define the PromptShield threat model and test vocabulary
- [ ] Create a portable format for prompt-security test cases
- [ ] Add baseline prompt-injection and jailbreak scenarios
- [ ] Add sensitive-data and secret-exposure checks
- [ ] Support repeatable local evaluations
- [ ] Generate actionable findings and security reports
- [ ] Add CI-friendly regression testing
- [ ] Publish reference patterns for safer agents and tool use
- [ ] Document attack coverage, limitations, and false-positive handling

## Example future workflow

```text
Define workflow → Map trust boundaries → Run attack cases
       ↓                  ↓                    ↓
   Record inputs      Identify tools       Capture behavior
       └──────────────────────┬──────────────────────┘
                              ↓
                 Review findings and harden controls
                              ↓
                    Re-run tests as regressions
```

## Project status

PromptShield is currently an early-stage project scaffold. The public repository contains the project README and license while the implementation, test corpus, and evaluation tooling are being developed.

Until those components are available, treat this README as the project direction—not as a description of completed functionality.

## Contributing

Contributions should make the threat model and expected security behavior clearer. A useful contribution should explain:

1. The attacker capability or failure mode being addressed
2. The trust boundary or workflow component involved
3. The expected secure behavior
4. How the behavior can be reproduced and tested
5. What limitations or false positives remain

Never include credentials, private customer data, or live attack material that could harm a real system.

## Responsible use

PromptShield is intended for authorized security testing and defensive engineering. Test only systems, models, data, and workflows that you own or are explicitly authorized to assess. Do not treat a passing evaluation as proof that an AI system is secure against all attacks.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
