# Documentation validation procedure

Status: author-check procedure only. Actual results are revision-bound PR submissions.

The completion stage uses `python3 scripts/check-docs.py --base BASE_SHA --subject SUBJECT_SHA`.
It requires a clean complete checkout, checks all tracked documents and the implementation
diff, runs both helper self-tests and six checkout regressions, then executes the unchanged
supplemental owning-ID/schema/ADR/proof/UAT assertions. Reports and command logs are stored
in `docs-check/`. `--stage bootstrap` retains bootstrap changed-artifact restrictions;
`--stage implementation` admits the actual workspace, migrations and delivery tooling.
Neither stage drops unchanged contract owners from validation. A source-only update must
still satisfy the complete contract package.

GitHub Actions capacity is exhausted by owner instruction. The workflow is manually
dispatchable only and invokes the same portable command; no hosted run is authorized or
claimed by this change. Historical failures remain visible at
[run 35648867633](https://github.com/jjjjguevara/llull-buzz/actions/runs/35648867633) and
[run 35658636251](https://github.com/jjjjguevara/llull-buzz/actions/runs/35658636251).

## Historical bootstrap procedure

The original bootstrap `check_provider_docs.py` had SHA-256
`131e4c8e5961cadbc028678dba1df881ccd392558cb033890130153a647b5cb3`.
The supplemental `check_profile_package.py` is SHA-256 `22f206f8100a386433093c98e65ec50aa0f682be4af1b118bfcea40acebfe870`.
Its immutable published source is linked in the submission. It adds owning capability,
required-port, commitment, component, assurance/UAT, JSON Schema/example and preservation
checks. It does not replace the original checkout checker with a weaker successful path.

## Materialization and commands

A complete checkout runs the existing workflow's original checker against exact HEAD/base:

```sh
python3 docs/bootstrap/check_provider_docs.py --self-test
python3 docs/bootstrap/check_provider_docs.py --base BASE_SHA --subject SUBJECT_SHA
```

The private-repository workflow retrieves that same immutable checker into RUNNER_TEMP;
its actual path appears in the recorded command. A missing workflow run is not a pass.
The supplement accepts a separately prepared source index from GitHub's exact PR diff/tree
read-back; it hashes every materialized changed file against its recorded Git blob:

```sh
python3 check_profile_package.py --self-test
python3 check_profile_package.py --root CHECKED_PACKAGE --index SOURCE_INDEX.json \
  --legacy check_provider_docs.py --output REPORT.json
```

A reconstruction is explicitly a complete **changed-document package**, not a complete Git
checkout or an executed `git diff --check`. The index names subject/base, changed paths and
remote Git blobs, referenced unchanged targets and preserved source identities. Local staged
checks do not certify a later published SHA. Final evidence is produced only after comparing
publication to the stated index and reading back the actual remote branch/tree. The report
stores commands/exits, checker identity, file SHA-256/Git blobs, counts, errors and limitations.
PR comments bind the final head without pretending an evidence-storage commit validates itself.

## Assertions and tool footprint

The original parser/format/link/component/capability assertions remain. The supplement also
checks strict duplicate keys, Python checker syntax, owning IDs rather than corpus substrings,
proposed ADR/null-acceptance state, mandatory human-case links, closed JSON Schema and positive/
negative synthetic examples. Mail fixture digest checks use only their ASCII/no-float subset;
they are not a new general RFC 8785 implementation. Fiscal vectors check documented bytes/hashes,
not fiscal runtime. Schema-valid but unauthorized examples remain expected semantic denials,
not passes of a cryptographic or provider test.

Author tooling uses Python 3, PyYAML 6.0.3 (MIT), jsonschema 4.26.0 (MIT), standard-library
hashing/parsing and existing Git for checkout checks. Parsers were already available for the
local check; no selected product dependency was installed. The original GitHub workflow pins
checkout/upload-artifact actions, does no product build and retains its actual artifact/report.
Tool distribution/license metadata: [PyYAML](https://pypi.org/project/PyYAML/6.0.3/) and
[jsonschema](https://pypi.org/project/jsonschema/4.26.0/).

External references receive syntax checks plus recorded primary-source qualification. The
checker does not probe HTTP availability, log into private services or validate a link by
executing an application. Unchanged references without anchors are verified against the
source tree; anchored targets must be materialized. Original source/ADR preservation is
established by remote diff/tree identities, not claimed from absent local source files.

## Evidence boundary

Retain initial failures and subsequent corrections; never edit a checker to suppress a valid
finding. Report author checks separately from the sole reviewer's independent assessment.
No runtime/security/performance certification, human UAT, fiscal/mail effect, deployment,
migration, reviewer approval, finding resolution or merge is performed by this procedure.
An unresolved owner license decision remains unresolved even when document checks pass.
