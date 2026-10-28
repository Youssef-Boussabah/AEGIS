"""Rebuild the four-role PDF revision from the approved original PDFs in Git.

Requires PyMuPDF. Run from any directory; no network access or source PDF edits.
Original technical pages are preserved except for explicitly listed blocks.
"""
from pathlib import Path
import subprocess
import fitz

ROOT = Path(__file__).resolve().parents[2]
BASE = '7752d390113a02a239e140d4565943d1733c3347'
INK = (0.126, 0.157, 0.176)


def original(name):
    data = subprocess.run(['git', 'show', f'{BASE}:docs/{name}.pdf'], cwd=ROOT,
                          check=True, capture_output=True).stdout
    return fitz.open(stream=data, filetype='pdf')


def blocks(page):
    return [(b, ' '.join(s['text'].strip() for l in b['lines'] for s in l['spans']))
            for b in page.get_text('dict')['blocks'] if 'lines' in b]


def replace(page, needle, text, size=None, bold=False, width=None):
    matches = [(b, t) for b, t in blocks(page) if needle in t]
    if len(matches) != 1:
        raise ValueError((page.number + 1, needle, len(matches)))
    b, _ = matches[0]
    rect = fitz.Rect(b['bbox'])
    span = b['lines'][0]['spans'][0]
    size = size or span['size']
    # The next block defines available space; never shrink text to force a fit.
    following = [q['bbox'][1] for q, _ in blocks(page)
                 if q['bbox'][1] > rect.y1 + .5 and q['bbox'][0] < rect.x1]
    bottom = min(following, default=750)
    if rect.y0 > 750:
        bottom = 780
    target = fitz.Rect(rect.x0, rect.y0 - 1, width or 558.6, bottom)
    page.add_redact_annot(rect + (-.2, -.2, .2, .2), fill=(1, 1, 1))
    page.apply_redactions(images=0, graphics=0)
    if '\n' not in text and fitz.get_text_length(text, fontname='hebo' if bold else 'helv', fontsize=size) <= target.width:
        page.insert_text((target.x0, target.y0 + size), text, fontsize=size,
                         fontname='hebo' if bold else 'helv', color=INK)
        return
    remaining = page.insert_textbox(target, text, fontsize=size,
                                   fontname='cour' if '\n' in text else ('hebo' if bold else 'helv'),
                                   color=INK, lineheight=1.10 if '\n' in text else 1.24)
    if remaining < 0:
        raise ValueError(f'Overflow page {page.number+1}, {needle}: {remaining}')


def body_page(doc, index, heading, items):
    p = doc[index]
    for link in p.get_links():
        p.delete_link(link)
    p.add_redact_annot(fitz.Rect(45, 40, 570, 745), fill=(1, 1, 1))
    p.apply_redactions(images=0, graphics=0)
    y = 47
    def para(text, size=11, bold=False, gap=10):
        nonlocal y
        font = 'hebo' if bold else 'helv'
        words = text.split()
        lines, line = [], ''
        for word in words:
            trial = f'{line} {word}'.strip()
            if fitz.get_text_length(trial, fontname=font, fontsize=size) > 505:
                lines.append(line); line = word
            else:
                line = trial
        if line:
            lines.append(line)
        h = (len(lines) - 1) * size * 1.28 + size * 1.6 + 1
        r = fitz.Rect(53.4, y, 558.6, y + h)
        if p.insert_textbox(r, '\n'.join(lines), fontname=font, fontsize=size,
                            color=INK, lineheight=1.28) < 0:
            raise ValueError('Body overflow')
        y += h + gap
    para(heading, 22, True, 10)
    for kind, text in items:
        para(text, 13 if kind == 'h' else 11, kind == 'h', 7)
    if y > 737:
        raise ValueError(f'Page {index+1} too long: {y}')


def finish(doc, name):
    # Update old issue hyperlinks even on pages whose text layout is unchanged.
    mapping = {1: 9, 2: 9, 3: 10, 4: 10, 5: 12, 6: 11}
    for page in doc:
        replace(page, '28 OCT 2026', '28 OCT 2026  |  FOUR ROLES  |  EVIDENCE c995857', size=7)
        # Reinsert page numbering because the original footer is a single block.
        page.insert_text((285, 772), f'{page.number+1} / {len(doc)}', fontsize=8)
        for link in page.get_links():
            uri = link.get('uri', '')
            for old, new in mapping.items():
                if uri == f'https://github.com/Youssef-Boussabah/AEGIS/issues/{old}':
                    link['uri'] = f'https://github.com/Youssef-Boussabah/AEGIS/issues/{new}'
                    page.update_link(link)
    doc.set_metadata({**doc.metadata, 'subject': 'Four-role revision; historical evidence c995857'})
    doc.save(ROOT / 'docs' / f'{name}.pdf', garbage=4, deflate=True)


def user_guide():
    d = original('AEGIS_USER_GUIDE')
    body_page(d, 2, 'Four roles, one product', [
        ('p', 'These are technical responsibilities, not person assignments. The same roles appear in Technical Documentation section 10 and GitHub issues 9-12. Each role has one working branch; all changes return to dev/integration through pull requests.'),
        ('h', 'A  Core Platform, Shield & Integration'),
        ('p', 'Build the protection engine and the workflow around it. Own Core, API, CLI, LLVM Shield and its adapter, ImageLab, CI and repository integration. Make the existing application build reproducible, then measure which transformations survive optimization and add one tested defense.'),
        ('p', 'First delivery: clean-clone checks, a repeatable protection-to-application run, and a Shield improvement with correctness, final-binary retention, runtime and size evidence. Adaptive optimization follows trustworthy measurements.'),
        ('p', 'Done when: another engineer can reproduce the run; supported and unsupported inputs are handled correctly; failures are visible; protection claims stay within the evidence.'),
        ('p', 'Branch: feat/core-shield. Issue #9. Technical Documentation 10A (two pages).'),
        ('h', 'B  Adversarial AI Lab & Mirage'),
        ('p', 'Build the experiment that tests whether protection helps. Run paired Ghidra and model reconstruction attempts with equal access and budgets. Compile candidates in isolation and score them against hidden tests. Then use the same Lab to evaluate harmless decoys.'),
        ('p', 'First delivery: one reproducible baseline/protected comparison with hashes, model settings, budgets, transcripts and independent scoring. Follow with a deterministic Mirage variant and a matched no-decoy control.'),
        ('p', 'Done when: both authorization gates remain enforced; errors and inconclusive trials are recorded; decoys preserve behavior; any benefit is measured against a control.'),
        ('p', 'Own attack_lab/ and protectors/mirage/. Coordinate LLVM hooks with A. Branch: feat/lab-mirage. Issue #10. Technical Documentation 10B (two pages).'),
    ])
    body_page(d, 3, 'Four roles continued', [
        ('h', 'C  Frontend & Product Experience'),
        ('p', 'Build the complete developer workflow: supported-input guidance, upload, protection settings, job progress, errors, artifacts and evidence. Connect to the real API and create a reproducible demonstration. Own platform/dashboard/ and presentation assets.'),
        ('p', 'First delivery: a usable interface that submits a real LLVM job and displays its actual status and report, followed by an ImageLab walkthrough. Coordinate job-listing and download endpoints with A; those capabilities are not in the documented API baseline.'),
        ('p', 'Done when: identifiers, hashes and results come from actual jobs; loading, empty, unauthorized and failed states work; the demo can be repeated without special local knowledge.'),
        ('p', 'Branch: feat/frontend. Issue #11. Technical Documentation 10C.'),
        ('h', 'D  Signature, Sentinel & Verification'),
        ('p', 'Make build records verifiable. Start with an offline signed manifest linked to the final artifact digest, then add machine-readable policy records. Watermarking is a separate optional research task. Own provenance/ and sentinel/.'),
        ('p', 'First delivery: manifest creation, public-key verification, clear failure states and tests for modified artifacts, modified manifests, wrong keys and malformed data. Keep private keys out of the repository and logs.'),
        ('p', 'Done when: valid records verify against an explicitly trusted key and invalid records fail. Later policy and watermark work must have its own acceptance evidence; a policy notice alone cannot force compliance.'),
        ('p', 'Branch: feat/signature-sentinel. Issue #12. Technical Documentation 10D.'),
        ('h', 'How the work meets'),
        ('p', 'A produces and integrates protected builds. B tests reconstruction and decoys. D signs records for fixed artifact bytes. C presents the real workflow and evidence. Shared contracts need review by the affected roles. External benchmark issue #7 spans all four roles.'),
    ])
    replace(d[4], '2 Create your working branch', '2 Check out your role branch', bold=True)
    replace(d[4], 'For a new checkout', 'For a fresh clone, the example below checks out role A. Substitute your role branch from pages 3-4. For an existing checkout, inspect git status and follow CONTRIBUTING.md before switching.')
    replace(d[4], 'git switch -c feat/your-area', 'git clone https://github.com/Youssef-Boussabah/AEGIS.git\ncd AEGIS\ngit switch feat/core-shield\ngit merge --ff-only origin/dev/integration\ngit rev-parse HEAD', size=9.5)
    replace(d[5], 'My workstream is', 'My role is [A-D and name]. My issue is [link]. My allowed paths are [paths]. The first deliverable is [specific behavior]. Its acceptance tests are [checks]. Repository actions I authorize are [edit and test only, or named additional actions].')
    replace(d[5], 'Repository and source index', 'Reference index: Technical Documentation 13. Both guides use roles A-D; technical evidence remains the historical c995857 baseline.', size=9)
    finish(d, 'AEGIS_USER_GUIDE')


def technical():
    d = original('AEGIS_TECHNICAL_DOCUMENTATION')
    # A table cell can share a block with adjacent cells: replace only this line.
    p = d[0]
    rects = p.search_for('The six assignments, dependencies, and acceptance criteria.')
    assert len(rects) == 1
    r = rects[0]
    p.add_redact_annot(r, fill=(1,1,1)); p.apply_redactions(images=0, graphics=0)
    p.insert_text((r.x0, r.y1-2), 'The four roles, dependencies, and acceptance criteria.', fontsize=10)
    replace(d[7], 'Planning mismatch:', 'Benchmark issue #7 tracks PhotoCraft, reVC and Mattermost. These remain evaluation targets, not special cases in the engine. Pin revisions and establish baseline builds before claiming support. [S10]')
    replace(d[10], 'git switch -c feat/your-area', 'git clone https://github.com/Youssef-Boussabah/AEGIS.git\ncd AEGIS\ngit switch feat/core-shield\ngit merge --ff-only origin/dev/integration\ngit rev-parse HEAD\n\nuv venv .venv\nuv pip install --python .venv/bin/python \\\n  -c core/requirements-dev.lock \\\n  -e \'./core[dev]\' -e \'./platform/api[dev]\' \\\n  -e \'./platform/cli[dev]\'\n.venv/bin/pytest\n\nclang --version\nopt --version\nllvm-config --version\ncommand -v clang opt llvm-config', size=9.2)
    titles = {13:'10A  Core platform and integration',14:'10A  Shield development',15:'10B  Adversarial AI Lab',16:'10B  Mirage research',17:'10D  Signature, Sentinel & Verification',18:'10C  Frontend & Product Experience'}
    tracking = {
        13:'Tracking: Issue #9. Branch: feat/core-shield. Role A covers this page and Shield development on the next page. Roles are independent of person assignments.',
        14:'Tracking: Issue #9. Branch: feat/core-shield. This is the Shield part of role A.',
        15:'Tracking: Issue #10. Branch: feat/lab-mirage. Role B owns attack_lab/ and protectors/mirage/. Deliver the Lab comparison before Mirage research.',
        16:'Tracking: Issue #10. Branch: feat/lab-mirage. This is the Mirage part of role B. Own protectors/mirage/; coordinate shared LLVM changes with role A.',
        17:'Tracking: Issue #12. Branch: feat/signature-sentinel. Role D owns provenance/ and sentinel/. Start with offline signing; policy and watermark work follow.',
        18:'Tracking: Issue #11. Branch: feat/frontend. Role C owns platform/dashboard/ and presentation assets. Coordinate API and ImageLab code changes with role A.'}
    for i, title in titles.items():
        old = next(t for _, t in blocks(d[i]) if t.startswith('10 '))
        replace(d[i], old, title, size=20, bold=True)
        replace(d[i], 'Tracking:', tracking[i], size=10)
    replace(d[13], 'Maintain a coherent system', 'Role A owns Core, API, CLI, LLVM Shield and its adapter, ImageLab, root governance, docs and CI. This page covers platform and integration work; the next page covers Shield. Keep both compatible as roles B, C and D develop.')
    replace(d[13], '3. Update AGENTS.md', '3. Keep root guidance, both PDFs and module instructions aligned with roles A-D.')
    replace(d[13], 'ImageLab. Publish ownership', 'Update them alongside implementation and contract changes.')
    replace(d[19], "The repository's public default branch", 'dev/integration is the default integration branch. Both guides and the repository now use roles A-D and the same four feature branches. See CONTRIBUTING.md for checkout, synchronization and PR rules. CI and branch protection remain separate infrastructure work; documentation does not enable them. [S1, S10]')
    replace(d[19], 'Assign named owners;', 'Select and pin the first external components; define Lab isolation and its result schema; choose a model deployment; decide signing format and trust management; agree API extensions and multi-stage artifact lineage; set cost budgets and release-branch policy. Person assignments are separate from this technical plan.')
    replace(d[22], 'S10 Planning.', 'S10 Planning. Issues #9-#12 and docs/TEAM_WORKSTREAMS.md define roles A-D. Issue #7 tracks PhotoCraft, reVC and Mattermost. Issues #1-#6 are historical.')
    # Put C before D while keeping the six implementation-detail pages.
    d.move_page(18, 17)
    finish(d, 'AEGIS_TECHNICAL_DOCUMENTATION')


if __name__ == '__main__':
    user_guide()
    technical()
    print('Updated both PDFs; render and inspect before committing.')
