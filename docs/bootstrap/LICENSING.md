# Original-work licensing and distribution

Decision: **Apache-2.0**, approved by Josué Guevara on 2026-09-21 for original
llull-buzz code and documentation at this stage. Source: the owner's explicit execution
instruction, recorded verbatim in [the PR decision record](https://github.com/jjjjguevara/llull-buzz/pull/1#issuecomment-5756846038).
This answers the formerly pending original-work choice; it is not inferred from repository
visibility or upstream licensing. The unselected proprietary alternative remains historical.

## Scope and application

The root [LICENSE](../../LICENSE) contains the Apache License, Version 2.0, January 2004.
Unless an individual file or component identifies third-party terms, this license applies
to this repository's original source, documentation, configuration, schemas, examples and
author-check tooling. It does not change another repository's license, grant ownership of
consumer data or credential material, or license hosted model/service access. No new runtime
release, deployment, commercial warranty or source implementation is implied by this decision.

Copyright 2026 llull-buzz contributors.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use the
original work except in compliance with the License. You may obtain a copy at
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.

## Third-party distinctions and distribution

[The component register](../architecture/components/REGISTRY.yaml) retains each upstream,
library, tool and hosted-service license independently. Only its `owned.*` records and
original-project default become Apache-2.0. Referenced upstream code is not copied or
relicensed by this documentation change. A later distribution includes the applicable
license texts, attribution and any required upstream NOTICE material for what it actually
ships. Do not invent a bundled dependency inventory or remove existing third-party notices.

The [official license text and application instructions](https://www.apache.org/licenses/LICENSE-2.0)
were consulted on 2026-09-21. The committed standard text is the local common-licenses copy
of that license, with unchanged terms; its exact byte hash belongs to the validation report.
No extra NOTICE condition or license restriction is introduced by this scope record.

## Review and execution disposition

PCR1 accepted the technical consolidation at `d45c1793b859815127bf9986e084500e2ad9b115`;
the owner has now answered its sole remaining license item. Current status references and
component defaults reflect that answer. Historical unanswered entries remain dated history.
The three architectural ADRs keep their existing lifecycle metadata; this specific license
approval is not a fabricated broad ADR acceptance or a runtime/UAT certificate. The existing
realization ticket records the answer and submission, while the designated reviewer retains
finding-resolution and merge-readiness authority. No PR is merged by this change.
