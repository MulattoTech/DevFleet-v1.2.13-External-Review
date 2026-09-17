# DevFleet — Post-v1.2.13 Feature Roadmap

> **Status:** Future roadmap / feature-request backlog. This document is intentionally separate from the current v1.2.13 release-certification evidence.
>
> **Primary intent:** Preserve the product direction in a form that future AI agents and human contributors can quickly recover, reason about, and decompose into implementation plans.

---

## AI Recall Capsule

If an AI is resuming DevFleet later, remember these requested product directions:

1. **Modularize DevFleet into clear systems/engines** so a small UI or subsystem change does not force broad repository-wide rebuild/revalidation or touch unrelated code.
2. **Add a Ralph-loop style bounded iterative execution mode** (inspired by `snarktank/ralph`) so a task can repeatedly plan/build/test/fix until its acceptance contract is satisfied. This is the conceptual basis for a future DevFleet **"Ultron" mode**, but must remain bounded, observable, recoverable, and safe.
3. **Replace/upgrade the Dashboard project launcher with a 120x-style planning/launch layer** (working name: **DevFleet Foundry**) that accepts a new idea, existing conversation, existing/stalled project, or built-in template; performs guided intake; and produces a complete project-planning/handoff folder.
4. Foundry must generate **requirements, blueprint/architecture, acceptance criteria, tasks/roadmap, risks/decisions, architect prompts, builder prompts, agent/tool handoffs, and durable project state** from one canonical structured plan.
5. **Add project progress tracking / roadmap / scrum / Mission Control** so every project has visible phases, tasks, acceptance state, blockers, current/next work, and historical checkpoints.
6. **Allow project creation from a ChatGPT-style freeform prompt**, with an AI planning/preprocessing layer that converts the prompt into the canonical project plan and then configures the DevFleet environment appropriately.
7. **Fix stopped-project UX.** A stopped VM/container/project must be unmistakably shown as stopped, live-data tabs/actions must not pretend to load forever, and runtime-dependent controls must be disabled or explain why they are unavailable.
8. External-agent handoff (Codex, Claude Code, Cursor, etc.) should remain supported, but DevFleet's differentiator is that it can continue from planning into **native workspace/runtime creation and managed execution** instead of stopping at the handoff package.
9. The 120x-inspired planning layer is **not itself an agent runtime, container manager, or multi-agent orchestrator**. Keep planning/specification concerns cleanly separated from DevFleet's runtime/orchestration layer.

---

# Roadmap Theme 1 — Modular DevFleet Architecture

## Problem

DevFleet has grown into a broad application where unrelated concerns can become tightly coupled. A small UI change, release-tooling change, or subsystem change should not require large portions of the repository to be recreated, retouched, rebuilt, or recertified when those portions are semantically unrelated.

## Requested direction

Refactor toward **explicit modules/engines with narrow contracts**, stable schemas, and subsystem-specific tests.

Suggested conceptual boundaries:

- **Project Planning / Foundry Engine** — intake, specification, templates, blueprint generation.
- **Project State Engine** — canonical project plan, roadmap, requirements, decisions, risks, task state, checkpoints.
- **Template Engine** — project/business templates and template versioning/migrations.
- **Project Creation Engine** — turns a validated plan into a DevFleet workspace and metadata record.
- **Runtime Engine** — VM/container lifecycle and runtime providers.
- **Resource / Capacity Engine** — CPU/RAM/disk profiles and admission decisions.
- **Agent Adapter / Handoff Engine** — Codex, Claude Code, Cursor, generic AGENTS.md/skills/config exports.
- **Progress / Mission Control Engine** — task/sprint/proof/evidence state.
- **Execution Loop Engine** — bounded Ralph/Ultron iterative work.
- **Observability / UX Capability Engine** — live/stopped/reachable/transitioning capability state.
- **Release / Evidence Engine** — validation, packaging, evidence, candidate/release identity.

## Architectural requirements

- UI should depend on stable service/API contracts, not reach deeply into runtime implementation.
- Shipping identity should distinguish which modules actually changed.
- Tests should be scoped so unrelated changes do not invalidate unrelated subsystems unnecessarily.
- Canonical structured state should be generated once and rendered into human/agent-specific views instead of maintaining many independent sources of truth.
- Modules should have explicit ownership, inputs, outputs, versioning, and migration rules.

## Definition of success

A small change to one UI surface or planning template can be built/tested/released without touching unrelated runtime, installer, project-lifecycle, or release subsystems except where their contract actually changed.

---

# Roadmap Theme 2 — Ralph Loop / "Ultron" Iterative Completion Mode

Reference:

- https://github.com/snarktank/ralph

## Goal

Add a DevFleet-native bounded iterative loop that can keep working a task until its **acceptance contract** is satisfied rather than stopping after a single agent pass.

Conceptually:

```text
Task / Acceptance Contract
        ↓
Plan
        ↓
Implement
        ↓
Test / Verify
        ↓
Satisfied? ── yes ──> Complete + Evidence
    │
    no
    ↓
Diagnose / Adjust
    ↓
Next bounded iteration
```

## Requirements

- Bounded iteration count / wall-clock / usage budget.
- Explicit acceptance criteria and verification commands.
- Durable iteration state and checkpoints.
- Per-iteration evidence and failure reason.
- Safe resume after interruption/context exhaustion.
- No unbounded autonomous loop.
- No hidden mutation outside the project's authorized scope.
- Escalation policy when repeated iterations stop making meaningful progress.
- Ability to distinguish product defect, environment defect, ambiguous requirement, and test/harness defect.
- Optional human approval gates for destructive or high-risk actions.

## Relationship to "Ultron" mode

Ralph-style iteration can provide the core execution semantics for a future **Ultron mode**: autonomous continuation toward a defined project goal, but with bounded control, transparent state, recovery, and proof rather than an uncontrolled forever-agent.

---

# Roadmap Theme 3 — DevFleet Foundry: 120x-Style Project Launcher / Planning Layer

Reference product:

- https://120x.ai/launcher/

## Important boundary

The 120x-style component is a **planning / specification / handoff layer**.

It is specifically **not** the runtime, VM/container manager, or multi-agent orchestrator.

For DevFleet, Foundry should sit **in front of the existing project-creation/runtime machinery**. DevFleet can then continue beyond the handoff into native environment creation, which is a major product advantage.

## Required entry paths

Foundry should accept at least:

1. **New idea** — freeform description of something to build.
2. **Built-in template** — CRM, portal, tracker, dashboard, internal tool, etc.
3. **Existing conversation/chat** — ingest a prior ChatGPT/Claude/etc. discussion and extract project intent.
4. **Existing project/codebase** — adopt a brownfield repo and reconstruct current truth.
5. **Stalled project / rescue mode** — ingest repo + logs + handoffs + audit reports and create a recovery plan.

## Guided intake

The launcher should run an adaptive interview rather than a fixed giant form.

Potential intake domains:

- project purpose / North Star;
- users/personas;
- must-have features;
- explicitly out-of-scope behavior;
- data model;
- APIs/integrations;
- UI/UX requirements;
- deployment/runtime target;
- language/framework preference;
- security/privacy constraints;
- performance/reliability expectations;
- testing expectations;
- local vs cloud dependencies;
- project scale/resource needs;
- branding/design preferences where relevant;
- uncertainty / assumptions requiring later verification.

Questions should be skipped when already inferable from imported context.

## Canonical project model

Do **not** let many Markdown files become independent competing truths.

Generate one canonical versioned structured model, e.g.:

```text
.devfleet/project-plan.json
```

Then render human/agent-specific artifacts from it.

The canonical plan should contain IDs and traceability for:

- requirements;
- acceptance criteria;
- features;
- architecture decisions;
- risks;
- assumptions;
- data entities;
- APIs/interfaces;
- tasks;
- phases/sprints;
- dependencies;
- runtime/environment requirements;
- evidence/verification requirements.

## Generated project package

A target project could resemble:

```text
project/
├── .devfleet/
│   ├── project.json
│   ├── project-plan.json
│   ├── planner.json
│   └── runtime.json
│
├── planning/
│   ├── NORTH-STAR.md
│   ├── CURRENT-STATE.md
│   ├── DECISIONS.md
│   ├── RISKS.md
│   └── ASSUMPTIONS.md
│
├── requirements/
│   ├── REQUIREMENTS.md
│   ├── ACCEPTANCE.md
│   ├── DATA-MODEL.md
│   └── UX.md
│
├── architecture/
│   ├── BLUEPRINT.md
│   ├── COMPONENTS.md
│   ├── API.md
│   ├── SECURITY.md
│   └── diagrams/
│
├── build/
│   ├── ROADMAP.md
│   ├── SPRINTS.md
│   ├── current/
│   └── history/
│
├── handoff/
│   ├── ARCHITECT.md
│   ├── BUILDER.md
│   ├── CODEX.md
│   ├── CLAUDE.md
│   ├── CURSOR.md
│   └── AGENTS.md
│
└── evidence/
```

Exact naming is not mandatory; canonical-model semantics are.

## Generated artifact requirements

At minimum:

- project overview / North Star;
- requirements with traceable IDs;
- acceptance criteria;
- technical blueprint;
- architecture/components;
- data model;
- API/interface contracts;
- UX/design requirements where relevant;
- technology/stack decisions;
- architecture decision records;
- assumptions and open questions;
- risk register + mitigations;
- phased roadmap;
- ordered tasks linked to requirements;
- verification/test expectations;
- architect prompt;
- builder prompt;
- Codex/Claude/Cursor/generic agent handoff instructions;
- current project state / next action.

## DevFleet-native continuation

Unlike a handoff-only product, DevFleet should be able to continue:

```text
Idea / Existing Context
        ↓
Foundry Intake
        ↓
Canonical Plan
        ↓
Validated Artifacts
        ↓
DevFleet Project Creation
        ↓
VM / Container / Workspace
        ↓
Dependencies / Bootstrap
        ↓
Agent Builder Contract
        ↓
Build / Test / Verify
        ↓
Mission Control / Next Sprint
```

External handoff remains supported, but is optional.

---

# Roadmap Theme 4 — Foundry Template Library

Build a curated library of high-quality templates rather than a handful of hard-coded project types.

Example categories:

- CRM;
- customer/client portal;
- ticket/help desk;
- inventory management;
- applicant tracker;
- time/expense tracker;
- reporting/dashboard;
- knowledge base;
- quoting/invoicing;
- developer tool;
- API/service;
- automation system;
- AI/RAG tool;
- data pipeline;
- DevOps/infrastructure tool;
- monitoring/backup tool;
- educational tool;
- custom generic project.

Templates should seed the canonical project plan, not bypass guided intake. Users must still be able to customize scope and requirements.

## Reference / inspiration projects

Evaluate these as reusable methodology/components/reference material. Perform license and attribution review before incorporating source.

- https://github.com/ersinkoc/project-architect
  - guided discovery;
  - specification / implementation / tasks / branding / PROMPT pipeline;
  - agent-oriented handoff generation.

- https://ai-blueprint.dev/
  - durable project state;
  - project/build plans;
  - feature history;
  - existing-codebase/adoption concepts;
  - Mission-Control-like project context.

- https://github.com/open-gsd/get-shit-done-redux
  - discuss → plan → execute → verify → ship;
  - context management;
  - persistent state / fresh-context work patterns.

- https://github.com/shaunpalmer/ai-project-starter
  - North Star / current truth / decision history / checkpoint concepts;
  - project lifecycle scaffold.
  - **License must be confirmed before reusing source.**

- https://github.com/heldernoid/agentic-build-templates
  - large corpus of agent-buildable project specifications;
  - architecture docs, plans, design specs and template ideas.

- https://github.com/Hesper-Labs/architect
  - visual spec authoring;
  - project wizard;
  - architecture canvas/diagrams;
  - ADR/risk register;
  - validation/export UX.

- https://github.com/FredAntB/Spec-Driven-Development
  - requirement IDs;
  - requirement → task → acceptance traceability;
  - shared cross-agent specification model.

## Template quality requirements

- Versioned schema.
- Template migrations.
- Traceable requirements.
- No hidden assumptions.
- Explicit optional vs required fields.
- Validation before project creation.
- Automated fixture/eval tests for generated artifacts.
- Ability to update planning methodology without silently corrupting existing projects.

---

# Roadmap Theme 5 — Mission Control / Roadmap / Scrum Progress Tracking

## Goal

Every DevFleet project should have a visible, durable project progress model.

The UI should answer immediately:

- What are we building?
- What phase/sprint are we in?
- What is complete?
- What is currently executing?
- What is blocked?
- Why is it blocked?
- What is the next action?
- Which requirements are satisfied?
- Which acceptance criteria have proof?
- Which decisions changed and why?
- What remains before the project is considered done?

## Suggested views

- Overall roadmap / phases.
- Sprint board: backlog / ready / active / blocked / verify / done.
- Requirement coverage matrix.
- Acceptance/proof status.
- Current task + next action.
- Blocker timeline.
- Decision history / ADRs.
- Risk register.
- Build/test history.
- Agent/iteration history.
- Release/deployment status.

This should be backed by canonical structured state, not merely UI-only cards.

---

# Roadmap Theme 6 — Prompt-Driven Project Creation

## Requested UX

Allow the user to create a project from a ChatGPT-style prompt, for example:

> Build an inventory-management application for a small repair business. It needs parts, vendors, reorder thresholds, purchase orders, customer jobs, barcode support, and reports.

The user should not first have to know:

- the correct DevFleet template;
- runtime type;
- framework;
- resource profile;
- exact file structure;
- agent prompt format.

## Required intelligence layer

A planner should convert the prompt into a normalized intake state, identify missing high-impact decisions, ask only the necessary follow-up questions, and compile the canonical project plan.

Potential implementation sources:

- native DevFleet planner service;
- CodexPro-derived planning component;
- model/provider abstraction compatible with local or remote models.

Do not couple project-plan semantics permanently to one model/provider.

## Guardrails

- AI suggestions never silently become authoritative without schema validation.
- Assumptions are recorded explicitly.
- Unknown/inferred information is marked.
- Security/runtime/resource decisions have deterministic validators.
- Project creation happens only after the plan passes validation.

---

# Roadmap Theme 7 — Existing / Stalled Project Rescue

This is a first-class Foundry mode, not an afterthought.

Inputs may include:

- repository/worktree;
- existing project metadata;
- prior chats;
- logs;
- failed test output;
- audit bundles;
- handoff files;
- issue/PR history;
- roadmap/spec documents.

The rescue process should reconstruct:

- current truth;
- intended goal;
- completed work;
- stale assumptions;
- current blockers;
- candidate hypotheses;
- acceptance criteria;
- next bounded diagnostic/fix plan.

Output should be a clean canonical plan plus an explicit recovery sprint and builder/architect handoff.

DevFleet v1.2.13 itself is a motivating example of why this capability is valuable.

---

# Roadmap Theme 8 — Fix Stopped Project / Runtime UX

## Current problem

On pages such as:

`/projects/m-techlabs-job-finder?tab=overview`

a stopped project can be indicated only by a small, low-contrast **stopped** label. The rest of the page can still look interactive, and users can navigate to runtime-dependent tabs/actions that attempt to retrieve data from a VM/container that is not running.

This creates:

- misleading loading states;
- endless waits/timeouts;
- unnecessary requests;
- unclear distinction between unavailable and broken;
- poor accessibility/visibility of runtime state.

## Required capability-driven UX

Runtime state should be a first-class page state.

When a project is stopped:

- show a prominent stopped/offline banner or status treatment;
- use accessible high-contrast styling;
- make Start Project / Start Runtime the obvious primary action;
- disable or gate runtime-dependent actions/tabs;
- do not issue live metrics/health/log requests known to be impossible;
- explain why the data is unavailable;
- show last-known/cached values only when clearly labeled as stale;
- distinguish **Stopped**, **Starting**, **Running**, **Stopping**, **Unreachable**, **Error**, and **Provisioning** states;
- automatically refresh/re-enable capabilities after a successful start.

The backend already has/should maintain a server-authoritative capability model for actions such as:

- live metrics;
- health;
- logs;
- tests;
- workspace access;
- start/stop/restart.

The dashboard must consume that capability model rather than independently guessing from UI state.

## Definition of success

A stopped VM/container can never leave the user staring at an indefinite "loading" state for data that the server already knows cannot be retrieved.

---

# Recommended Delivery Sequence

This sequence is intentionally **after v1.2.13 is certified**.

## Phase A — Architectural foundation

1. Define module/engine boundaries.
2. Define canonical Project Plan schema.
3. Define requirement/task/acceptance IDs and traceability.
4. Define version/migration strategy.
5. Introduce capability-driven stopped-runtime UX.

## Phase B — Foundry MVP

1. New idea flow.
2. Template flow.
3. Guided intake.
4. Canonical project-plan compiler.
5. Requirements/blueprint/acceptance/task output.
6. Codex/Claude/generic builder handoff.
7. Existing DevFleet `create_project` integration.

## Phase C — Mission Control

1. Roadmap and sprint state.
2. Requirement/acceptance coverage.
3. Current/next task.
4. Blockers.
5. History/checkpoints/decisions/risks.

## Phase D — Brownfield / rescue

1. Existing-repo adoption.
2. Chat/context import.
3. Stalled-project reconstruction.
4. Recovery sprint generation.

## Phase E — Ralph / Ultron execution

1. Bounded iterative loop.
2. Acceptance-driven repeat execution.
3. Durable iterations/evidence.
4. Pause/resume/recovery.
5. Human approval gates.
6. Integration with Mission Control.

## Phase F — Template/library expansion and polish

1. Curate 40–75 strong templates initially.
2. Template search/categories/customization.
3. Visual architecture/spec editor.
4. Diagram support.
5. External-agent adapter polish.
6. Artifact quality/evaluation fixtures.

---

# Rough Development Estimate

These are planning estimates, not commitments.

## Useful prototype

**~3–5 focused working days** with AI-assisted implementation:

- new project / basic templates;
- guided intake;
- requirements;
- blueprint;
- acceptance criteria;
- project folder;
- basic Codex/Claude handoff.

## Strong first DevFleet Foundry release

**~10–15 focused working days / roughly 100–160 focused engineering hours** with parallel AI-assisted work:

- polished intake;
- 40–60+ curated templates;
- conversation/context prefill;
- existing/stalled-project flows;
- canonical plan + validation;
- Architect/Builder packs;
- Mission Control basics;
- DevFleet native workspace/runtime handoff;
- external-agent handoffs;
- method versioning;
- useful automated tests/evals.

## Mature / polished implementation

**~3–5 weeks / roughly 160–240 engineering hours**:

- richer diagrams/spec editor;
- advanced template UX;
- migration compatibility;
- stronger rescue analysis;
- artifact editing/preview;
- extensive evals;
- high visual/interaction polish;
- robust failure/recovery UX.

---

# Product Naming / UX Direction

Working name proposal:

## **DevFleet Foundry**

Top-level flows:

```text
Foundry
├── New Project
├── From Template
├── Import Conversation
├── Adopt Existing Project
└── Rescue Stalled Project
```

Conceptual lifecycle:

```text
Foundry → Architect → Blueprint → Launch → Mission Control
```

This name is provisional; functionality and boundaries matter more than branding.

---

# Non-Goals / Boundaries

- Do not turn the planning layer itself into the runtime/container manager.
- Do not let Ralph/Ultron become an unbounded uncontrolled autonomous loop.
- Do not bind canonical project state to one AI vendor.
- Do not maintain multiple Markdown documents as independent competing authorities.
- Do not sacrifice DevFleet ownership/safety boundaries for convenience.
- Do not automatically copy code from reference projects without license/attribution review.
- Do not treat templates as substitutes for validation or guided intake.

---

# Future AI Handoff Instruction

When planning or implementing these roadmap items, future AI agents should:

1. Read this document first.
2. Treat it as product-direction input, not proof that implementation already exists.
3. Reconcile against the live DevFleet repository and current architecture before editing.
4. Preserve the separation between planning, canonical state, runtime management, execution, and evidence.
5. Prefer incremental modules with explicit contracts over another monolithic subsystem.
6. Create acceptance criteria and regression tests before broad implementation.
7. Update this roadmap with implemented/superseded status rather than silently changing intent.
